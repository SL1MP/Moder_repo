// Эталон: пакет semver из npm (npm i semver), путь задаётся SEMVER_PATH.
const semver = (await import(process.env.SEMVER_PATH || 'semver')).default
import fs from 'node:fs'

const OUT = process.env.VERCHECK_OUT || '.'

const PKGS = ['express','lodash','react','webpack','axios','eslint','typescript','jest',
              'chalk','commander','debug','rxjs','vue','next','babel-loader','ws','yargs']

const headers = { Accept: 'application/vnd.npm.install-v1+json' }
const ranges = new Set()
const versions = new Set()

for (const name of PKGS) {
  const resp = await fetch(`https://registry.npmjs.org/${name}`, { headers })
  if (!resp.ok) { console.error('skip', name, resp.status); continue }
  const doc = await resp.json()
  for (const v of Object.keys(doc.versions)) versions.add(v)
  for (const meta of Object.values(doc.versions)) {
    for (const r of Object.values(meta.dependencies || {})) ranges.add(r)
    for (const r of Object.values(meta.devDependencies || {})) ranges.add(r)
  }
}

const versionList = [...versions].filter((v) => semver.valid(v)).sort(semver.compare)
// Прореживаем: полный перебор дал бы миллионы пар без прироста покрытия.
const sample = versionList.filter((_, i) => i % 7 === 0).slice(0, 300)
const rangeList = [...ranges].filter((r) => semver.validRange(r) !== null)

const cases = []
for (const spec of rangeList) {
  for (const version of sample) {
    cases.push({ spec, version, expected: semver.satisfies(version, spec) })
  }
}
fs.writeFileSync(`${OUT}/npm_cases.json`, JSON.stringify(cases))

const compare = []
for (let i = 0; i + 1 < versionList.length; i += 3) {
  compare.push({ a: versionList[i], b: versionList[i + 1], want: semver.compare(versionList[i], versionList[i + 1]) })
}
fs.writeFileSync(`${OUT}/npm_compare.json`, JSON.stringify(compare))
console.log('ranges:', rangeList.length, 'versions:', sample.length, 'cases:', cases.length, 'compare:', compare.length)
