// Package sbom builds CycloneDX documents from the exact artifact bytes that
// passed moderation. It never pulls a package again.
package sbom

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var supported = map[string]bool{
	"npm": true, "nuget": true, "pypi": true, "maven": true,
	"go": true, "conan": true, "docker": true,
}

const moderatedGroup = "com.ptsecurity.moderated"

func Supports(manager string) bool { return supported[strings.ToLower(strings.TrimSpace(manager))] }

// Input identifies a moderated package and the bytes saved by DownloadStep.
type Input struct {
	Manager        string
	Name           string
	DisplayName    string
	Version        string
	RawVersion     string
	LicenseSPDX    string
	LicenseRaw     string
	ArtifactSHA256 string
	Payload        []byte
	// Vulnerabilities — результаты реально выполненного шага OSV для этой
	// версии. Корпоративный generate_from_packagelist_license.py добавляет
	// PURL и лицензии, но CVE не создаёт; здесь они встраиваются в стандартную
	// секцию CycloneDX и связываются с компонентом через affects.
	Vulnerabilities []Vulnerability
}

type Vulnerability struct {
	ID            string
	Aliases       []string
	Summary       string
	URL           string
	Severity      string
	CVSSVector    string
	CVSSScore     float64
	FixedVersions []string
}

// Document is one CycloneDX JSON file. Docker returns one per real platform.
type Document struct {
	Filename    string
	Platform    string
	SpecVersion string
	Body        []byte
}

type Generator interface {
	Generate(ctx context.Context, in Input) ([]Document, error)
}

type DefaultGenerator struct {
	SyftBinary string
	Now        func() time.Time
}

func (g DefaultGenerator) Generate(ctx context.Context, in Input) ([]Document, error) {
	manager := strings.ToLower(strings.TrimSpace(in.Manager))
	if !supported[manager] {
		return nil, fmt.Errorf("SBOM не поддерживается для менеджера %q", in.Manager)
	}
	if manager == "docker" {
		return g.generateDocker(ctx, in)
	}
	doc, err := g.generatePackage(in)
	if err != nil {
		return nil, err
	}
	return []Document{doc}, nil
}

func (g DefaultGenerator) now() time.Time {
	if g.Now != nil {
		return g.Now().UTC()
	}
	return time.Now().UTC()
}

type cdxDocument struct {
	BomFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	Serial          string             `json:"serialNumber"`
	Version         int                `json:"version"`
	Metadata        cdxMetadata        `json:"metadata"`
	Components      []cdxComponent     `json:"components"`
	Vulnerabilities []cdxVulnerability `json:"vulnerabilities,omitempty"`
}

type cdxMetadata struct {
	Timestamp string         `json:"timestamp"`
	Tools     []cdxTool      `json:"tools"`
	Component cdxComponent   `json:"component"`
}

type cdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxComponent struct {
	Type     string       `json:"type"`
	BomRef   string       `json:"bom-ref"`
	Group    string       `json:"group,omitempty"`
	Name     string       `json:"name"`
	Version  string       `json:"version"`
	PURL     string       `json:"purl"`
	Hashes   []cdxHash    `json:"hashes,omitempty"`
	Licenses []cdxLicense `json:"licenses,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxLicense struct {
	License cdxLicenseValue `json:"license"`
}

type cdxLicenseValue struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type cdxVulnerability struct {
	BomRef         string             `json:"bom-ref"`
	ID             string             `json:"id"`
	Source         *cdxVulnSource     `json:"source,omitempty"`
	Ratings        []cdxVulnRating    `json:"ratings,omitempty"`
	Description    string             `json:"description,omitempty"`
	Recommendation string             `json:"recommendation,omitempty"`
	Affects        []cdxVulnAffect    `json:"affects"`
}

type cdxVulnSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}
type cdxVulnRating struct {
	Score    float64 `json:"score,omitempty"`
	Severity string  `json:"severity,omitempty"`
	Method   string  `json:"method,omitempty"`
	Vector   string  `json:"vector,omitempty"`
}
type cdxVulnAffect struct {
	Ref string `json:"ref"`
}

// Enrich adds moderation results that are only known after the independent
// SBOM generator has finished. This split is what allows SBOM generation and
// OSV scanning to run in parallel: the later VuMana upload barrier combines
// them without making either scanner wait for the other.
func Enrich(body []byte, licenseSPDX, licenseRaw string, findings []Vulnerability) ([]byte, error) {
	// Generic maps are deliberate: Docker documents come from Syft and carry
	// dependency graphs, properties and evidence fields unknown to the small
	// structures used by our package generator. A typed unmarshal/marshal
	// would silently erase those fields and turn a useful image SBOM into a
	// shell containing only components.
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("CycloneDX не разобран для обогащения: %w", err)
	}
	if format, _ := doc["bomFormat"].(string); format != "CycloneDX" {
		return nil, fmt.Errorf("ожидался CycloneDX, получено %q", format)
	}
	var licenses []any
	if value := strings.TrimSpace(licenseSPDX); value != "" {
		licenses = []any{map[string]any{"license": map[string]any{"id": value}}}
	} else if value := strings.TrimSpace(licenseRaw); value != "" {
		licenses = []any{map[string]any{"license": map[string]any{"name": value}}}
	}
	var metadataComponent map[string]any
	if metadata, ok := doc["metadata"].(map[string]any); ok {
		metadataComponent, _ = metadata["component"].(map[string]any)
	}
	if metadataComponent != nil {
		metadataComponent["group"] = moderatedGroup
	}
	if len(licenses) > 0 {
		if metadataComponent != nil {
			metadataComponent["licenses"] = licenses
		}
		components, _ := doc["components"].([]any)
		metadataRef, _ := metadataComponent["bom-ref"].(string)
		for _, raw := range components {
			component, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			ref, _ := component["bom-ref"].(string)
			if ref == metadataRef || len(components) == 1 {
				component["licenses"] = licenses
			}
		}
	}
	affectsRef := ""
	if metadataComponent != nil {
		affectsRef, _ = metadataComponent["bom-ref"].(string)
	}
	components, _ := doc["components"].([]any)
	if strings.TrimSpace(affectsRef) == "" && len(components) > 0 {
		if component, ok := components[0].(map[string]any); ok {
			affectsRef, _ = component["bom-ref"].(string)
		}
	}
	seen := make(map[string]bool, len(findings))
	vulnerabilities := make([]any, 0, len(findings))
	for _, finding := range findings {
		id := preferredVulnerabilityID(finding.ID, finding.Aliases)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		v := map[string]any{
			"bom-ref": "vulnerability:" + id, "id": id,
			"source": map[string]any{"name": "OSV"},
		}
		if description := strings.TrimSpace(finding.Summary); description != "" {
			v["description"] = description
		}
		if affectsRef != "" {
			v["affects"] = []any{map[string]any{"ref": affectsRef}}
		}
		if rawURL := strings.TrimSpace(finding.URL); rawURL != "" {
			v["source"].(map[string]any)["url"] = rawURL
		}
		severity := normalizeSeverity(finding.Severity, finding.CVSSScore)
		if finding.CVSSScore > 0 || severity != "unknown" || strings.TrimSpace(finding.CVSSVector) != "" {
			method := "other"
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(finding.CVSSVector)), "CVSS:3") {
				method = "CVSSv3"
			}
			rating := map[string]any{"severity": severity, "method": method}
			if finding.CVSSScore > 0 {
				rating["score"] = finding.CVSSScore
			}
			if vector := strings.TrimSpace(finding.CVSSVector); vector != "" {
				rating["vector"] = vector
			}
			v["ratings"] = []any{rating}
		}
		if len(finding.FixedVersions) > 0 {
			v["recommendation"] = "Обновить до исправленной версии: " + strings.Join(finding.FixedVersions, ", ")
		}
		vulnerabilities = append(vulnerabilities, v)
	}
	if len(vulnerabilities) > 0 {
		doc["vulnerabilities"] = vulnerabilities
	} else {
		delete(doc, "vulnerabilities")
	}
	result, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("сериализация обогащённого CycloneDX: %w", err)
	}
	return append(result, '\n'), nil
}

func (g DefaultGenerator) generatePackage(in Input) (Document, error) {
	purl, group, name, err := packagePURL(in.Manager, in.Name, in.Version)
	if err != nil {
		return Document{}, err
	}
	component := cdxComponent{
		Type: "library", BomRef: purl, Group: group, Name: name,
		Version: in.Version, PURL: purl,
	}
	metadataComponent := component
	metadataComponent.Group = moderatedGroup
	if sha := strings.TrimSpace(in.ArtifactSHA256); sha != "" {
		component.Hashes = []cdxHash{{Alg: "SHA-256", Content: sha}}
	}
	if license := strings.TrimSpace(in.LicenseSPDX); license != "" {
		component.Licenses = []cdxLicense{{License: cdxLicenseValue{ID: license}}}
	} else if license := strings.TrimSpace(in.LicenseRaw); license != "" {
		component.Licenses = []cdxLicense{{License: cdxLicenseValue{Name: license}}}
	}
	doc := cdxDocument{
		BomFormat: "CycloneDX", SpecVersion: "1.4", Version: 1,
		Serial: deterministicSerial(in.Manager + "\x00" + in.Name + "\x00" + in.Version + "\x00" + in.ArtifactSHA256),
		Metadata: cdxMetadata{
			Timestamp: g.now().Format(time.RFC3339),
			Tools: []cdxTool{{Vendor: "Positive Technologies", Name: "moderation-service", Version: "1"}},
			Component: metadataComponent,
		},
		// Kept in components as well because the existing corporate consumer
		// reads this list rather than metadata.component.
		Components: []cdxComponent{component},
	}
	seenVulnerabilities := make(map[string]bool, len(in.Vulnerabilities))
	for _, finding := range in.Vulnerabilities {
		id := preferredVulnerabilityID(finding.ID, finding.Aliases)
		if id == "" || seenVulnerabilities[id] {
			continue
		}
		seenVulnerabilities[id] = true
		v := cdxVulnerability{
			BomRef: "vulnerability:" + id, ID: id, Description: strings.TrimSpace(finding.Summary),
			Affects: []cdxVulnAffect{{Ref: purl}},
		}
		if rawURL := strings.TrimSpace(finding.URL); rawURL != "" {
			v.Source = &cdxVulnSource{Name: "OSV", URL: rawURL}
		} else {
			v.Source = &cdxVulnSource{Name: "OSV"}
		}
		severity := normalizeSeverity(finding.Severity, finding.CVSSScore)
		if finding.CVSSScore > 0 || severity != "unknown" || strings.TrimSpace(finding.CVSSVector) != "" {
			method := "other"
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(finding.CVSSVector)), "CVSS:3") {
				method = "CVSSv3"
			}
			v.Ratings = []cdxVulnRating{{
				Score: finding.CVSSScore, Severity: severity, Method: method,
				Vector: strings.TrimSpace(finding.CVSSVector),
			}}
		}
		if len(finding.FixedVersions) > 0 {
			v.Recommendation = "Обновить до исправленной версии: " + strings.Join(finding.FixedVersions, ", ")
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, v)
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return Document{}, fmt.Errorf("сериализация CycloneDX: %w", err)
	}
	body = append(body, '\n')
	return Document{
		Filename: safeFilename(in.Name) + "-" + safeFilename(in.RawVersion) + ".cdx.json",
		SpecVersion: "1.4", Body: body,
	}, nil
}

func preferredVulnerabilityID(primary string, aliases []string) string {
	for _, alias := range aliases {
		alias = strings.TrimSpace(alias)
		if strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
			return alias
		}
	}
	return strings.TrimSpace(primary)
}

func normalizeSeverity(value string, score float64) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "high", "medium", "low", "unknown":
		return strings.ToLower(strings.TrimSpace(value))
	}
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

func packagePURL(manager, rawName, version string) (purl, group, name string, err error) {
	manager = strings.ToLower(strings.TrimSpace(manager))
	rawName = strings.TrimSpace(rawName)
	version = strings.TrimSpace(version)
	if rawName == "" || version == "" {
		return "", "", "", fmt.Errorf("для SBOM нужны непустые имя и версия")
	}
	typeName := manager
	switch manager {
	case "go":
		typeName = "golang"
	case "maven":
		parts := strings.SplitN(rawName, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", "", "", fmt.Errorf("координаты Maven %q не имеют формат group:artifact", rawName)
		}
		group, name = parts[0], parts[1]
		return "pkg:maven/" + escapePURLPath(group) + "/" + escapePURLPath(name) + "@" + escapePURLVersion(version), group, name, nil
	}
	name = rawName
	return "pkg:" + typeName + "/" + escapePURLName(rawName) + "@" + escapePURLVersion(version), "", name, nil
}

func escapePURLName(value string) string {
	parts := strings.Split(value, "/")
	for i := range parts {
		parts[i] = escapePURLPath(parts[i])
	}
	return strings.Join(parts, "/")
}

func escapePURLPath(value string) string {
	// PathEscape leaves '+' ambiguous and escapes '@' as required for scoped npm.
	escaped := strings.ReplaceAll(url.PathEscape(value), "+", "%2B")
	return strings.ReplaceAll(escaped, "@", "%40")
}

func escapePURLVersion(value string) string { return escapePURLPath(value) }

func deterministicSerial(seed string) string {
	h := sha256.Sum256([]byte(seed))
	b := h[:16]
	// RFC 4122 version/variant bits, deterministic rather than random so a
	// retry of the same artifact does not manufacture a new identity.
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	hexv := hex.EncodeToString(b)
	return "urn:uuid:" + hexv[0:8] + "-" + hexv[8:12] + "-" + hexv[12:16] + "-" + hexv[16:20] + "-" + hexv[20:32]
}

var unsafeFilename = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeFilename(value string) string {
	value = strings.Trim(unsafeFilename.ReplaceAllString(value, "-"), "-.")
	if value == "" {
		return "package"
	}
	return value
}

type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Platform    ociPlatform       `json:"platform"`
	Annotations map[string]string `json:"annotations"`
}

type ociPlatform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant"`
	OSVersion    string `json:"os.version"`
}

type ociIndex struct {
	SchemaVersion int             `json:"schemaVersion,omitempty"`
	MediaType     string          `json:"mediaType,omitempty"`
	Manifests     []ociDescriptor `json:"manifests"`
}

func (g DefaultGenerator) generateDocker(ctx context.Context, in Input) ([]Document, error) {
	if strings.TrimSpace(g.SyftBinary) == "" {
		return nil, fmt.Errorf("не задан бинарник Syft")
	}
	dir, cleanup, err := extractOCILayout(in.Payload)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	platforms, err := dockerPlatforms(dir)
	if err != nil {
		return nil, err
	}
	if len(platforms) == 0 {
		return nil, fmt.Errorf("OCI index не содержит образов платформ")
	}
	indexPath := filepath.Join(dir, "index.json")
	originalIndex, err := os.ReadFile(indexPath)
	if err != nil { return nil, err }
	defer func() { _ = os.WriteFile(indexPath, originalIndex, 0o600) }()
	repository, purlName := dockerRepository(in.Name)
	tag := strings.SplitN(in.RawVersion, "@", 2)[0]
	docs := make([]Document, 0, len(platforms))
	for _, platform := range platforms {
		platformName := platform.Platform.OS + "/" + platform.Platform.Architecture
		if platform.Platform.OS == "" || platform.Platform.Architecture == "" {
			platformName = "unknown"
		}
		if platform.Platform.Variant != "" {
			platformName += "/" + platform.Platform.Variant
		}
		displayPlatform := platformName
		if platform.Platform.OSVersion != "" {
			displayPlatform += "@" + platform.Platform.OSVersion
		}
		// Point index.json directly at this manifest. Selecting only by
		// os/arch is ambiguous for Windows indexes containing several
		// os.version values; a one-manifest view guarantees that Syft scans
		// the descriptor represented by this document.
		platformIndex, err := json.Marshal(ociIndex{
			SchemaVersion: 2, MediaType: "application/vnd.oci.image.index.v1+json",
			Manifests: []ociDescriptor{platform},
		})
		if err != nil { return nil, err }
		if err := os.WriteFile(indexPath, platformIndex, 0o600); err != nil { return nil, err }
		// Syft's OciDirectory source does not support --platform (including
		// the version bundled in our image). index.json has already been
		// reduced to the exact manifest above, so asking Syft to select a
		// platform is both unnecessary and rejected before scanning starts.
		args := []string{"oci-dir:" + dir, "-o", "cyclonedx-json"}
		cmd := exec.CommandContext(ctx, g.SyftBinary, args...)
		out, runErr := cmd.CombinedOutput()
		if runErr != nil {
			message := strings.TrimSpace(string(out))
			if len(message) > 1000 {
				message = message[:1000] + "…"
			}
			return nil, fmt.Errorf("Syft для %s: %w: %s", platformName, runErr, message)
		}
		normalized, specVersion, err := normalizeDockerDocument(out, dockerRoot{
			Name: purlName, Repository: repository, Tag: tag,
			IndexDigest: dockerIndexDigest(in.Version), ManifestDigest: platform.Digest,
			Platform: displayPlatform, OS: platform.Platform.OS,
			Architecture: platform.Platform.Architecture, Variant: platform.Platform.Variant,
			OSVersion: platform.Platform.OSVersion,
		})
		if err != nil {
			return nil, fmt.Errorf("CycloneDX Syft для %s: %w", platformName, err)
		}
		docs = append(docs, Document{
			Filename: safeFilename(purlName) + "-" + safeFilename(tag) + "-" + safeFilename(displayPlatform) + ".cdx.json",
			Platform: displayPlatform, SpecVersion: specVersion, Body: normalized,
		})
	}
	return docs, nil
}

func extractOCILayout(payload []byte) (string, func(), error) {
	gz, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return "", func() {}, fmt.Errorf("артефакт Docker не является OCI tar.gz: %w", err)
	}
	defer gz.Close()
	dir, err := os.MkdirTemp("", "moderation-sbom-oci-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	tr := tar.NewReader(gz)
	count := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			cleanup()
			return "", func() {}, fmt.Errorf("распаковка OCI layout: %w", err)
		}
		count++
		if count > 200000 {
			cleanup()
			return "", func() {}, fmt.Errorf("OCI layout содержит слишком много файлов")
		}
		name := path.Clean(h.Name)
		if name == "." || path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			cleanup()
			return "", func() {}, fmt.Errorf("недопустимый путь в OCI layout: %q", h.Name)
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				cleanup(); return "", func() {}, err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				cleanup(); return "", func() {}, err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				cleanup(); return "", func() {}, err
			}
			_, copyErr := io.Copy(f, tr)
			closeErr := f.Close()
			if copyErr != nil { cleanup(); return "", func() {}, copyErr }
			if closeErr != nil { cleanup(); return "", func() {}, closeErr }
		default:
			cleanup()
			return "", func() {}, fmt.Errorf("неподдерживаемый элемент OCI layout %q", h.Name)
		}
	}
	for _, required := range []string{"oci-layout", "index.json"} {
		if st, err := os.Stat(filepath.Join(dir, required)); err != nil || !st.Mode().IsRegular() {
			cleanup()
			return "", func() {}, fmt.Errorf("OCI layout не содержит %s", required)
		}
	}
	return dir, cleanup, nil
}

func dockerPlatforms(dir string) ([]ociDescriptor, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil { return nil, err }
	var layout ociIndex
	if err := json.Unmarshal(raw, &layout); err != nil { return nil, err }
	if len(layout.Manifests) != 1 {
		return nil, fmt.Errorf("в OCI layout ожидался один корневой descriptor, получено %d", len(layout.Manifests))
	}
	root := layout.Manifests[0]
	rootRaw, err := os.ReadFile(blobPath(dir, root.Digest))
	if err != nil { return nil, fmt.Errorf("корневой manifest %s не прочитан: %w", root.Digest, err) }
	var index ociIndex
	if err := json.Unmarshal(rootRaw, &index); err != nil { return nil, err }
	if len(index.Manifests) == 0 {
		// Одиночный manifest: OCI layout descriptor не обязан содержать
		// platform, поэтому берём её из config blob образа.
		var manifest struct { Config ociDescriptor `json:"config"` }
		if json.Unmarshal(rootRaw, &manifest) == nil && manifest.Config.Digest != "" {
			if configRaw, readErr := os.ReadFile(blobPath(dir, manifest.Config.Digest)); readErr == nil {
				var config struct {
					OS, Architecture, Variant string
					OSVersion string `json:"os.version"`
				}
				if json.Unmarshal(configRaw, &config) == nil {
					root.Platform = ociPlatform{OS: config.OS, Architecture: config.Architecture,
						Variant: config.Variant, OSVersion: config.OSVersion}
				}
			}
		}
		return []ociDescriptor{root}, nil
	}
	seen := map[string]bool{}
	var out []ociDescriptor
	for _, d := range index.Manifests {
		if d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" ||
			(d.Platform.OS == "unknown" && d.Platform.Architecture == "unknown") {
			continue
		}
		if d.Platform.OS == "" || d.Platform.Architecture == "" || seen[d.Digest] {
			continue
		}
		seen[d.Digest] = true
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		a := out[i].Platform.OS + "/" + out[i].Platform.Architecture + "/" + out[i].Platform.Variant + "@" + out[i].Platform.OSVersion
		b := out[j].Platform.OS + "/" + out[j].Platform.Architecture + "/" + out[j].Platform.Variant + "@" + out[j].Platform.OSVersion
		return a < b
	})
	return out, nil
}

func blobPath(dir, digest string) string {
	algo, value, ok := strings.Cut(digest, ":")
	if !ok || algo == "" || value == "" { return filepath.Join(dir, "invalid") }
	return filepath.Join(dir, "blobs", algo, value)
}

type dockerRoot struct {
	Name, Repository, Tag, IndexDigest, ManifestDigest, Platform string
	OS, Architecture, Variant, OSVersion string
}

func normalizeDockerDocument(raw []byte, root dockerRoot) ([]byte, string, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil { return nil, "", err }
	spec, _ := doc["specVersion"].(string)
	if spec == "" { spec = "1.4" }
	purl := "pkg:oci/" + escapePURLName(root.Name) + "@" + escapePURLVersion(root.ManifestDigest)
	qualifiers := url.Values{}
	if root.OS != "" { qualifiers.Set("os", root.OS) }
	if root.Architecture != "" { qualifiers.Set("arch", root.Architecture) }
	if root.Variant != "" { qualifiers.Set("variant", root.Variant) }
	if root.OSVersion != "" { qualifiers.Set("os_version", root.OSVersion) }
	qualifiers.Set("repository_url", root.Repository)
	purl += "?" + qualifiers.Encode()
	component := map[string]any{
		"type": "container", "bom-ref": purl, "group": moderatedGroup, "name": root.Name,
		"version": root.ManifestDigest, "purl": purl,
		"properties": []map[string]string{
			{"name": "ptsecurity:docker:index-digest", "value": root.IndexDigest},
			{"name": "ptsecurity:docker:tag", "value": root.Tag},
			{"name": "ptsecurity:docker:platform", "value": root.Platform},
		},
	}
	metadata, _ := doc["metadata"].(map[string]any)
	if metadata == nil { metadata = map[string]any{} }
	metadata["component"] = component
	doc["metadata"] = metadata
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil { return nil, "", err }
	return append(body, '\n'), spec, nil
}

func dockerRepository(raw string) (repository, purlName string) {
	name := strings.Trim(strings.TrimSpace(raw), "/")
	parts := strings.Split(name, "/")
	registry := "index.docker.io"
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost") {
		registry, parts = parts[0], parts[1:]
	}
	if registry == "index.docker.io" && len(parts) == 1 {
		parts = append([]string{"library"}, parts...)
	}
	repository = registry + "/" + strings.Join(parts, "/")
	if len(parts) > 1 && parts[0] == "library" { parts = parts[1:] }
	return repository, strings.Join(parts, "/")
}

func dockerIndexDigest(version string) string {
	_, digest, ok := strings.Cut(version, "@")
	if ok { return digest }
	return ""
}
