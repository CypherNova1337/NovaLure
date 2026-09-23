# NovaLure

Finds the bugs that never show up in the response — by making the server call you.

![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![python](https://img.shields.io/badge/python-3.8%2B-3776AB?style=flat-square)

## What it does

Some vulnerabilities leave no trace in what you get back. You send a request
that makes the server fetch a URL of your choosing, and the page returns a
perfectly normal 200. Nothing looks wrong. The server made the request out of
sight, and you had no way to see it.

That's blind SSRF, and it's why scanners miss it.

The trick is to point the target at a host you control. If the server really
does fetch that URL, you see the connection arrive on your side — and that
arrival *is* the proof. You didn't need the response to tell you anything.

NovaLure automates that. It spins up an Interactsh session to receive callbacks,
sprays your target's parameters and headers with URLs pointing at it, and
watches what comes back. Anything that phones home is reported with the request
that caused it. It also fuzzes for open redirects while it's in there, since
it's already testing every URL-shaped parameter.

## Why you'd use it

- **Catches what nothing in the response would reveal** — blind SSRF is
  invisible to anything that only reads replies.
- **Tests headers as well as parameters**, because `X-Forwarded-Host` and
  friends reach code that trusts them.
- **Finds open redirects in the same pass**, which uses the same parameters.
- **Writes a Markdown report** you can hand over rather than screenshots of a
  terminal.
- **Can pull in its own targets** via assetfinder and httprobe, or take a list
  you already have.

## Install

```bash
git clone https://github.com/CypherNova1337/NovaLure
cd NovaLure
pip install -r requirements.txt
```

You also need the [Interactsh client](https://github.com/projectdiscovery/interactsh)
on your `PATH`. Optionally `assetfinder` and `httprobe` if you want NovaLure to
discover targets itself.

## Usage

```bash
python3 NovaLure.py -u example.com
```

Discovers hosts, probes them, tests everything, and writes
`NovaLure_Report.md`.

**Use a list you already have**

```bash
python3 NovaLure.py -i targets.txt -o report.md
```

**Skip discovery when your targets are already final**

```bash
python3 NovaLure.py -i live_urls.txt --skip-assetfinder --skip-httprobe
```

**Use your own Interactsh server**

```bash
python3 NovaLure.py -u example.com --interactsh-server https://oast.example
```

Worth it on a real engagement — the public server is shared, and some targets
block the default domain outright.

**Cut the open-redirect noise**

```bash
python3 NovaLure.py -u example.com --strict-redirects
```

Only reports a header-based redirect when an OAST hit confirms it.

## Options

| Flag | Default | What it does |
|---|---|---|
| `-u` | — | Single target domain or URL |
| `-i` | — | File of targets, one per line |
| `-o` | `NovaLure_Report.md` | Report file |
| `-t` | `10` | HTTP timeout, in seconds |
| `--interactsh-server` | `interact.sh` | Interactsh server to receive callbacks |
| `--skip-assetfinder` | off | Don't run subdomain discovery |
| `--skip-httprobe` | off | Don't probe for live hosts |
| `--no-test-open-redirects` | off | Turn off open-redirect fuzzing |
| `--strict-redirects` | off | Only report header redirects confirmed by a callback |
| `--keep-interactsh-log` | off | Keep the raw Interactsh JSON |
| `-v` / `-q` | off | More / less output |

## Good to know

- **Callbacks can be slow.** Some SSRFs fire from a queue or a cron job minutes
  or hours later. A quiet run isn't always a negative one.
- **The public Interactsh server is shared and well known.** Egress filters
  block it, and a quiet result may mean the domain was blocked rather than the
  bug absent. Self-host when it matters.
- **A DNS-only hit still counts.** If you see the lookup but no HTTP request,
  something resolved your host — that's server-side request behaviour worth
  reporting even without a full connection.
- **It needs outbound reachability.** If the target has no internet egress, the
  technique can't work, and that's a property of the target rather than a
  finding.

## Authorised use

Only against targets you own or that are in scope for an engagement or bounty
programme. Making a server contact infrastructure you control is exactly the
sort of thing that needs to be agreed in advance.

## License

MIT — see [LICENSE](LICENSE).
