# mythic_sync

[![Sponsored by SpecterOps](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fspecterops%2F.github%2Fmain%2Fconfig%2Fshield.json&style=flat)](https://github.com/specterops#ghostwriter)

[![Python Version](https://img.shields.io/badge/Python-3.10-brightgreen.svg)](.) [![License](https://img.shields.io/badge/License-BSD3-darkred.svg)](.) ![GitHub Release (Latest by Date)](https://img.shields.io/github/v/release/GhostManager/mythic_sync?label=Latest%20Release) ![GitHub Release Date](https://img.shields.io/github/release-date/GhostManager/mythic_sync?label=Release%20Date&color=blue)

The `mythic_sync` utility connects to a [Mythic](https://github.com/its-a-feature/Mythic) C2 server (>=3.0.0+) to ingest events and post these events to the [Ghostwriter](https://github.com/GhostManager/Ghostwriter) (>=v3.0.1) GraphQL API to create real-time activity logs.

This tool automatically logs all new agent callbacks and every operator's Mythic commands, comments, and output into Ghostwriter so operators can focus more on technical execution and less on manual and tedious logging and reporting activities.

The current version of `mythic_sync` requires Mythic >=v3.0.0 and Ghostwriter >=v3.0.1.

## Usage

### Getting Started

To authenticate to your instances of Mythic and Ghostwriter, you will need this information handy:

* Ghostwriter URL
* Ghostwriter Service Token
* Ghostwriter log ID
* Mythic credentials

#### Ghostwriter API Token & Activity Log

You can get your log's ID by opening the log's webpage and looking at the top of the page. You'll see "Oplog ID #" followed by a number. That's the ID number you need.

You'll want a Ghostwriter Service Token (prefixed with `gwst_`) with access to your target log ID. If you don't have one yet, you can create a new token under your profile.

Read more about tokens and how to create and manage them here: [https://www.ghostwriter.wiki/features/operation-logs/setting-up-automated-logging](https://www.ghostwriter.wiki/features/operation-logs/setting-up-automated-logging)

### Execute via Mythic 3.0+ and `mythic-cli`

For the easiest experience with `mythic_sync`, install it via the `mythic-cli` tool. When installed this way, the `mythic_sync` service will become part of your Mythic deployment. You can then use `mythic-cli` to manage `mythic_sync` (just like Mythic) and the service will come up and go down alongside your other Mythic services.

On your Mythic server, run: `sudo ./mythic-cli mythic_sync install github https://github.com/GhostManager/mythic_sync`

Follow the prompts to configure `mythic_sync` with your Mythic and Ghostwriter server configuration.

You can get your Ghostwriter Oplog ID by visiting your log in your web browser and looking at the top of the page or the URL. A URL with `/oplog/12/entries` means your Oplog ID is `12`.

```bash
sudo ./mythic-cli mythic_sync install github https://github.com/GhostManager/mythic_sync
[*] Creating temporary directory
[*] Cloning https://github.com/GhostManager/mythic_sync
Cloning into '/opt/Mythic/tmp'...
Please enter your GhostWriter API Key: eyJ0eXAiO...
Please enter your GhostWriter URL: https://ghostwriter.domain.com
Please enter your GhostWriter OpLog ID: 12
Please enter your Mythic API Key (optional):
[+] Added mythic_sync to docker-compose
[+] Successfully installed mythic_sync!
[+] Successfully updated configuration in .env
```

### Execute via Stand Alone Docker

Alternatively, you can use Docker and `docker-compose` to run the `mythic_sync` container. Use this option if you'd prefer to run `mythic_sync` on a different server than your Mythic containers or don't want to use `mythic-cli` to manage the service.

After cloning repository, open the `settings.env` file and fill in the variables with appropriate values. The following is an example:

```text
MYTHIC_IP=10.10.1.100
MYTHIC_PORT=7443
MYTHIC_USERNAME=mythic_admin
MYTHIC_PASSWORD=SuperSecretPassword
GHOSTWRITER_API_KEY=gwst_...
GHOSTWRITER_URL=https://ghostwriter.mydomain.com
GHOSTWRITER_OPLOG_ID=12
REDIS_HOSTNAME=redis
REDIS_PORT=6379
REDIS_DB=1
```

Set `MYTHIC_API_KEY` to authenticate with a Mythic API key instead of `MYTHIC_USERNAME` and
`MYTHIC_PASSWORD`.

The standalone Compose deployment stores entry mappings and pending tag updates in the named
`mythic_sync_redis` volume. Redis append-only persistence with `appendfsync always` is enabled so recreating the
`mythic_sync` application container does not discard pending work. Mythic installations default
to an embedded append-only Redis instance for compatibility. To preserve that data across service
recreation, configure Mythic's generated Compose service to mount a stable named volume at `/data`;
the Dockerfile's volume declaration alone does not guarantee that a replacement container will
reattach the same storage. Alternatively, `REDIS_HOSTNAME`, `REDIS_PORT`, and `REDIS_DB` can select
an external persistent Redis instance.

For an authenticated or TLS-protected external Redis service, set `REDIS_URL` instead of the three
individual Redis settings. The URL takes precedence and may include the database number, username,
and password. Its credentials are never written to the service log:

```text
REDIS_URL=rediss://sync-user:password@redis.example.com:6380/1
```

Once the environment variables are set up, you can launch the service by using `docker-compose`:

``` bash
docker-compose up
```

### Verify Successful Start-Up

Open your Ghostwriter log and look for an initial entry. You should see something like the following:

    > Initial entry from mythic_sync at: <server_ip>. If you're seeing this then oplog syncing is working for this C2 server!

If so, you're all set! Otherwise, check the logs from the docker container for error messages. Fetch the logs with:

`sudo ./mythic-cli logs mythic_sync`

## Troubleshooting

Ensure the host where `mythic_sync` is running has network access to the Ghostwriter and Mythic servers.

`mythic_sync` uses Redis to track events already sent to Ghostwriter and to retain pending tag
updates. Redis mappings are scoped by Mythic server and Ghostwriter oplog. Legacy mappings and
pending tag jobs are migrated automatically when first accessed after an upgrade.

Source IP normalization removes duplicate, loopback, unspecified, multicast, and IPv6 link-local
addresses to keep multi-adapter hosts readable. Private IPv4, CGNAT, IPv6 ULA, and globally routable
addresses are preserved because interface metadata is not available to identify container bridges
reliably.
If a queued tag job's entry no longer resolves by `entryIdentifier`, the worker removes it from
active retries but preserves its payload in the deployment's namespaced Redis dead-letter hash and
notifies Mythic. A later task update can create a fresh tag job for the current entry.

The dead-letter hash is named:

```text
mythic_sync:<oplog-id>:<mythic-host>:pending_tag_updates:dead_letter
```

The startup warning prints the exact key. For the standalone Compose deployment, inspect it with:

```bash
docker compose exec redis redis-cli -n 1 HGETALL \
  "mythic_sync:<oplog-id>:<mythic-host>:pending_tag_updates:dead_letter"
```

After investigating an individual job, remove only that field with `HDEL <hash-key> <entry-id>`.
There is intentionally no automatic dead-letter replay in this release; updating the corresponding
Mythic task creates a fresh tag job if Ghostwriter can resolve or recreate its oplog entry.

The embedded Redis process flushes and shuts down when the application container receives
`SIGTERM`. Both embedded and standalone configurations use synchronous AOF writes. Do not remove
or renew the Redis data volume during upgrades if queued work must survive.

At startup, the service logs the selected Redis endpoint and number of pending tag updates. A
successful Redis client construction is not sufficient: the service waits for `PING` to succeed
before subscribing to Mythic events.

Run only one `mythic_sync` instance for a given Mythic server and Ghostwriter oplog namespace.
This release does not coordinate tag workers across multiple active replicas.

### Manual Acceptance Checklist

Perform destructive checks only in a disposable test oplog.

1. Start `mythic_sync` and confirm the initialization entry appears once in Ghostwriter. Restart
   the service and confirm a duplicate initialization entry is not created.
2. Run a Mythic task and confirm Ghostwriter receives an oplog entry whose `entryIdentifier`
   matches the Mythic `agent_task_id`. Update the task and confirm the existing entry changes rather
   than creating a duplicate.
3. Delete that Ghostwriter entry, then update the Mythic task. Confirm the logs identify the stale
   Ghostwriter ID and `entryIdentifier`, and that the entry is found again or recreated.
4. Add, change, and remove tags on the Mythic task. Confirm Ghostwriter's corresponding `mythic:`
   tags converge to the current Mythic tags while any Ghostwriter tags without the `mythic:` prefix
   remain unchanged. Stale-target and dead-letter behavior is covered by the automated test suite.
5. With a stable Redis volume attached, note the startup pending/dead-letter counts, restart or
   recreate only the `mythic_sync` container, and confirm the counts and Redis data remain. Do not
   remove or renew the volume during this check.
6. Temporarily use a service token without the required test-oplog permission and confirm the error
   identifies the GraphQL operation, oplog or entry identifier, and likely permission problem without
   logging command or comment contents.

### Testing

Run the unit suite in the production dependency image:

```bash
docker build -t mythic-sync-test .
docker run --rm --entrypoint /opt/venv/bin/python \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$PWD:/workspace" -w /workspace \
  mythic-sync-test -m unittest -v
```

The suite covers retries, `ModelDoesNotExist` reconciliation, stale and deleted entries, Redis
migrations, tag queue processing,
authentication selection, timestamp and IP normalization, initialization idempotency, and
diagnostic redaction.

## References

- [Mythic](https://github.com/its-a-feature/Mythic) - Multi-platform C2 Framework
- [Ghostwriter](https://github.com/GhostManager/Ghostwriter) - Engagement Management and Reporting Platform
- [Ghostwriter's Official Documentation - Operation Logging w/ Ghostwriter](https://ghostwriter.wiki/features/operation-logs) - Guidance on operation logging setup and usage with Ghostwriter
- [Blog - Updates to Ghostwriter: UI and Operation Logs](https://posts.specterops.io/updates-to-ghostwriter-ui-and-operation-logs-d6b3bc3d3fbd_) - Initial announcement of the operation logging features in Ghostwriter
