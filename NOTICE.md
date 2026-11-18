# Notices

agent-white-hat is released under the MIT License (see `LICENSE`). It includes the following data from others.

- **`pah/data/popular-npm.txt`**: the names of the 5,000 most-downloaded npm packages, taken from
  [npm-high-impact](https://github.com/wooorm/npm-high-impact) 1.13.0 by Titus Wormer, MIT License, sorted by name.
  Used to recognize look-alike package names.
- **`pah/data/popular-pypi.txt`**: the names of 5,000 of the most-downloaded PyPI projects, from public PyPI download
  statistics (the ClickHouse PyPI dataset) as published by [top-pypi-packages](https://github.com/hugovk/top-pypi-packages)
  on 2026-11-01. Only the names are kept, normalized and sorted; download counts and ranks are not included.
- **`pah/data/known-npm.txt`** and **`pah/data/known-pypi.txt`**: the rest of the same two lists (all 17,338 names in
  npm-high-impact 1.13.0, and the 15,000 PyPI projects in top-pypi-packages of 2026-11-01), used only so that
  established packages are not reported as look-alikes of more popular ones.
- **`bench/fixtures/independent-sample.json`** and **`bench/results/*-independent.json`**: the paths, sizes and git
  blob ids of samples drawn from Datadog's
  [malicious software packages dataset](https://github.com/DataDog/malicious-software-packages-dataset) (Copyright
  Datadog, Inc., Apache License 2.0), with agent-white-hat's verdict on each. No sample is included in this
  repository; `bench/independent.py` downloads them into memory when it runs. The same files list the names, versions
  and digests of the popular PyPI and npm releases in the evaluation, which are not included either.
- **`bench/results/*-shellgate*.json`**: agent-white-hat's verdict on each row of the
  [Obfuscated-Shell Gate Benchmark](https://huggingface.co/datasets/FINAL-Bench/Obfuscated-Shell-Gate) dev split
  (VIDRAFT / FINAL-Bench, 2026, CC-BY-4.0), referenced by row id, family and disguise. The commands themselves are not
  included; `bench/shellgate.py` downloads the dev split into memory when it runs.

- **`scripts/fonts/`**: [Instrument Sans](https://github.com/Instrument/instrument-sans) (Copyright 2022 The Instrument
  Sans Project Authors) and [IBM Plex Mono](https://github.com/IBM/plex) (Copyright IBM Corp.), both under the SIL Open
  Font License 1.1, whose texts sit next to the fonts. They set the README figures, the social card and the plugin
  icon; the copies were taken from the font set bundled with Anthropic's open-source
  [canvas-design skill](https://github.com/anthropics/skills) (Apache 2.0).

Rule descriptions cite the public research and incident reports they are based on; the links are in `docs/rules.md`
and `docs/research.md`. The figures follow design guidance from Anthropic's open-source frontend-design and
canvas-design skills and the dataviz method; [docs/design.md](docs/design.md) records the choices.
