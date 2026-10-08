-- A version is shared by all requests. If a later request published that
-- version, every earlier non-cancelled request must reflect the artifact that
-- now exists, even when the earlier run stopped on a different error.

WITH approved_source AS (
    SELECT DISTINCT ON (ri.package_version_id)
           ri.package_version_id, ri.next_action,
           ps.message, ps.details, ps.started_at, ps.finished_at
    FROM request_item ri
    JOIN pipeline_step ps
      ON ps.request_item_id = ri.id
     AND ps.step_code = 'publish'
     AND ps.result = 'pass'
    WHERE ri.status = 'approved'
    ORDER BY ri.package_version_id, ri.id DESC
), targets AS (
    SELECT ri.id, src.message, src.details, src.started_at, src.finished_at
    FROM request_item ri
    JOIN approved_source src ON src.package_version_id = ri.package_version_id
    WHERE ri.status <> 'approved' AND ri.status <> 'cancelled'
)
UPDATE pipeline_step ps
SET result = 'pass',
    message = targets.message,
    details = targets.details,
    started_at = COALESCE(ps.started_at, targets.started_at),
    finished_at = COALESCE(targets.finished_at, CURRENT_TIMESTAMP)
FROM targets
WHERE ps.request_item_id = targets.id AND ps.step_code = 'publish';

WITH approved_source AS (
    SELECT DISTINCT ON (ri.package_version_id)
           ri.package_version_id, ri.next_action, ps.message
    FROM request_item ri
    JOIN pipeline_step ps
      ON ps.request_item_id = ri.id
     AND ps.step_code = 'publish'
     AND ps.result = 'pass'
    WHERE ri.status = 'approved'
    ORDER BY ri.package_version_id, ri.id DESC
)
UPDATE request_item ri
SET status = 'approved',
    current_step = 'publish',
    blocked_reason = src.message,
    next_action = src.next_action,
    waiting_since = NULL,
    finished_at = COALESCE(ri.finished_at, CURRENT_TIMESTAMP),
    attempts = 0,
    resume_from_step = NULL,
    updated_at = CURRENT_TIMESTAMP
FROM approved_source src
WHERE ri.package_version_id = src.package_version_id
  AND ri.status <> 'approved'
  AND ri.status <> 'cancelled';

-- Recalculate only requests participating in duplicate successful versions.
-- The CASE is kept identical to Repo.RecomputeRequestStatus.
WITH candidate_requests AS (
    SELECT DISTINCT ri.request_id
    FROM request_item ri
    WHERE ri.status = 'approved'
      AND ri.current_step = 'publish'
      AND EXISTS (
          SELECT 1
          FROM request_item sibling
          WHERE sibling.package_version_id = ri.package_version_id
            AND sibling.id <> ri.id
            AND sibling.status = 'approved'
      )
)
UPDATE moderation_request mr
SET status = CASE
        WHEN NOT EXISTS (
            SELECT 1 FROM request_item ri WHERE ri.request_id = mr.id
        ) THEN 'pending'
        WHEN NOT EXISTS (
            SELECT 1 FROM request_item ri
            WHERE ri.request_id = mr.id AND ri.status <> 'cancelled'
        ) THEN 'cancelled'
        WHEN EXISTS (
            SELECT 1 FROM request_item ri
            WHERE ri.request_id = mr.id AND ri.status IN ('queued', 'running')
        ) THEN 'pending'
        WHEN EXISTS (
            SELECT 1 FROM request_item ri
            WHERE ri.request_id = mr.id AND ri.status = 'awaiting_security'
        ) THEN 'awaiting_security'
        WHEN EXISTS (
            SELECT 1 FROM request_item ri
            WHERE ri.request_id = mr.id
              AND ri.status IN ('awaiting_legal', 'license_claimed')
        ) THEN 'awaiting_legal'
        WHEN EXISTS (
            SELECT 1 FROM request_item ri
            WHERE ri.request_id = mr.id AND ri.status = 'quarantined'
        ) THEN 'quarantined'
        WHEN NOT EXISTS (
            SELECT 1 FROM request_item ri
            WHERE ri.request_id = mr.id
              AND ri.status <> 'cancelled'
              AND ri.status <> 'approved'
        ) THEN 'approved'
        WHEN NOT EXISTS (
            SELECT 1 FROM request_item ri
            WHERE ri.request_id = mr.id
              AND ri.status <> 'cancelled'
              AND ri.status NOT IN ('approved', 'dry_run')
        ) THEN 'dry_run'
        WHEN EXISTS (
            SELECT 1 FROM request_item ri
            WHERE ri.request_id = mr.id AND ri.status = 'approved'
        ) THEN 'partially_approved'
        WHEN EXISTS (
            SELECT 1 FROM request_item ri
            WHERE ri.request_id = mr.id AND ri.status = 'failed'
        ) THEN 'failed'
        ELSE 'rejected'
    END,
    updated_at = CURRENT_TIMESTAMP
WHERE mr.id IN (SELECT request_id FROM candidate_requests);

-- Older workers emitted one security event to both roles when publish was
-- waiting for two decisions. Remove those already-misrouted notifications
-- from legal-only accounts; real DevSecOps (including users with both roles)
-- keep their notification.
DELETE FROM notification n
USING "user" u
WHERE n.user_id = u.id
  AND n.event = 'request_awaits_security'
  AND u.roles ? 'legal'
  AND NOT (u.roles ? 'devsecops');
