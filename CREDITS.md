# Credits

Written and maintained by Prinnmesz Sessroj as a personal project.

This toolkit stands on other people's work. None of their code is copied into
this repository.

| Project | How it is used here | Licence |
|---|---|---|
| [pgrls](https://github.com/pgrls/pgrls) | Installed as a pinned dependency (0.57.1) and run unmodified. It is the RLS analyser; this toolkit only calls it. | MIT |
| [database-sentinel](https://github.com/Farenhytee/database-sentinel) | Source of three ideas, each reimplemented from scratch: scanning a web project for leaked keys, probing anonymous access with HEAD requests so that no row is downloaded, and enforcing read-only in two layers. | MIT for the repository; its Python server and agent are AGPL-3.0 and were not copied |
| [Supabase agent skills](https://github.com/supabase/agent-skills): `supabase` 0.1.2 and `supabase-postgres-best-practices` 1.1.1 | The working method in `skills/supabase-web-care/SKILL.md` was written with their guidance as a reference. The skill tells the agent to consult them and does not restate them. | MIT (as declared by `supabase-postgres-best-practices`) |
| [supabase-security-skill](https://github.com/Perufitlife/supabase-security-skill) | Reviewed while designing the guard rails. Several rules in the skill exist because of behaviour seen there that this toolkit deliberately avoids, such as calling functions to see whether they are callable. | see its repository |

A comparison of every file here against those sources found no shared prose;
the only overlaps are standard SQL phrases such as catalog joins and the usual
local stand-in for `auth.uid()`.

The first version of the skill text was drafted with AI assistance in the
author's own sessions and has been rewritten and extended since.
