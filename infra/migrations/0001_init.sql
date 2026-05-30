create extension if not exists pgcrypto;

create table if not exists projects (
    id uuid primary key,
    name text not null,
    slug text not null unique,
    created_at timestamptz not null default now()
);

create table if not exists api_keys (
    id uuid primary key,
    project_id uuid not null references projects(id) on delete cascade,
    name text not null,
    key_hash text not null unique,
    created_at timestamptz not null default now(),
    revoked_at timestamptz
);

create table if not exists devices (
    id uuid primary key,
    project_id uuid not null references projects(id) on delete cascade,
    external_device_id text not null,
    display_name text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (project_id, external_device_id)
);

create table if not exists device_fingerprints (
    id uuid primary key,
    project_id uuid not null references projects(id) on delete cascade,
    device_id uuid references devices(id) on delete set null,
    device_fingerprint_hash text not null,
    platform text not null,
    created_at timestamptz not null default now(),
    unique (project_id, device_fingerprint_hash)
);

create table if not exists protected_app_builds (
    id uuid primary key,
    project_id uuid not null references projects(id) on delete cascade,
    platform text not null,
    client_version text not null,
    file_hash text not null,
    status text not null default 'allowed',
    created_at timestamptz not null default now(),
    unique (project_id, platform, file_hash)
);

create table if not exists protection_runs (
    id uuid primary key,
    project_id uuid not null references projects(id) on delete cascade,
    device_id uuid references devices(id) on delete set null,
    platform text not null,
    client_version text,
    file_hash text,
    device_fingerprint_hash text,
    nonce text not null,
    started_at timestamptz not null default now(),
    expires_at timestamptz not null,
    ended_at timestamptz,
    last_heartbeat_at timestamptz,
    status text not null default 'active'
);

create table if not exists events (
    id uuid primary key,
    project_id uuid not null references projects(id) on delete cascade,
    session_id uuid references protection_runs(id) on delete cascade,
    device_id uuid references devices(id) on delete set null,
    event_type text not null,
    payload jsonb not null default '{}',
    created_at timestamptz not null default now()
);

create table if not exists detections (
    id uuid primary key,
    project_id uuid not null references projects(id) on delete cascade,
    session_id uuid references protection_runs(id) on delete cascade,
    device_id uuid references devices(id) on delete set null,
    rule_id text not null,
    severity text not null,
    risk_delta integer not null default 0,
    reasons jsonb not null default '[]',
    evidence jsonb not null default '{}',
    created_at timestamptz not null default now()
);

create table if not exists risk_scores (
    id uuid primary key default gen_random_uuid(),
    project_id uuid not null references projects(id) on delete cascade,
    device_id uuid not null references devices(id) on delete cascade,
    score integer not null check (score >= 0 and score <= 100),
    severity text not null,
    reasons jsonb not null default '[]',
    calculated_at timestamptz not null default now()
);

create table if not exists bans (
    id uuid primary key,
    project_id uuid not null references projects(id) on delete cascade,
    device_id uuid not null references devices(id) on delete cascade,
    status text not null check (status in ('clean', 'suspicious', 'review_required', 'confirmed', 'appealed', 'revoked')),
    reason text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists appeals (
    id uuid primary key default gen_random_uuid(),
    ban_id uuid not null references bans(id) on delete cascade,
    device_id uuid not null references devices(id) on delete cascade,
    message text not null,
    status text not null default 'open',
    created_at timestamptz not null default now(),
    resolved_at timestamptz
);

create table if not exists audit_logs (
    id uuid primary key,
    project_id uuid references projects(id) on delete cascade,
    device_id uuid references devices(id) on delete set null,
    actor_type text not null,
    actor_id text,
    action text not null,
    metadata jsonb not null default '{}',
    created_at timestamptz not null default now()
);

create index if not exists idx_protection_runs_project on protection_runs(project_id);
create index if not exists idx_protection_runs_device on protection_runs(device_id);
create index if not exists idx_events_session on events(session_id);
create index if not exists idx_detections_project on detections(project_id);
create index if not exists idx_audit_project_created on audit_logs(project_id, created_at desc);
