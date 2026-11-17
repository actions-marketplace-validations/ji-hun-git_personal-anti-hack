# How the figures look, and why

The README figures, the social card and the plugin icon are drawn by
[`scripts/make_figures.py`](../scripts/make_figures.py) from the files in `bench/results/`: every number in them is
read from a result, never typed. They are HTML and CSS, rendered to PNG at twice their size by headless Chrome or
Edge, in light and dark and in English and Korean.

## The idea: a case file

agent-white-hat's work is evidence: a command an agent was about to run, the file and line that decided it, a count
from a benchmark anyone can rerun. The figures show that evidence and nothing else. The one bold device is a
highlighter mark on the line that decided an outcome, the way an analyst marks a printed log. The mark is a white hat.

## Tokens

| Role | Light | Dark |
| --- | --- | --- |
| Ink (text, lines, the mark's tile) | `#13213c` | `#e6edf3` |
| Secondary text | `#59636e` | `#9198a1` |
| Hairline | `#d1d9e0` | `#3d444d` |
| Panel (a log or a terminal) | `#f6f8fa` | `#151b23` |
| Marker (evidence only) | `#ffe45e` | `#e8c547` |
| Verdict: pass / caught | `#12805c` | `#1f9a72` |
| Verdict: warn / asked | `#b8800a` | `#c08a10` |
| Verdict: block / denied / missed | `#bb3a32` | `#bb3a32` |
| No answer (neutral) | `#8c959f` | `#6e7681` |

The verdict colors were checked with the dataviz skill's validator against GitHub's page backgrounds (`#ffffff` and
`#0d1117`): lightness band, chroma, color-blind separation of neighbors (worst 9.4 light, 8.8 dark, target 8) and
contrast all pass. A verdict color always comes with its word or icon, never alone. Labels inside a fill are white,
or near-black where white would fall under 4.5:1 (amber in both modes, green in dark mode).

Each figure carries its page's background (white, or GitHub's dark `#0d1117`) with rounded corners. GitHub picks the
light or dark version by the operating system's setting, which can differ from the reader's GitHub theme; a
transparent figure would then put dark ink on a dark page. Where the two agree, the figure blends into the page; where
they do not, it reads as a clean panel. Logs and terminals carry their own panel inside it.

## Type

[Instrument Sans](https://github.com/Instrument/instrument-sans) for everything, numbers included, and
[IBM Plex Mono](https://github.com/IBM/plex) only for what is really a command, a path or terminal output. Korean
falls back to the system's Korean face (Malgun Gothic, Apple SD Gothic Neo). Both fonts are in `scripts/fonts/` with
their SIL Open Font License texts.

Headlines are set in one color and sentence case; no eyebrow labels, no all-caps labels, no words joined with middle
dots. Large standalone numbers use proportional figures.

## Rules

- **Evidence over decoration.** If a shape does not carry information, it goes.
- **Numbers only where there is a sequence.** The steps of a chain and the order of the guard's checks are numbered;
  nothing else is.
- **Charts follow the dataviz method:** tall segmented bars for a whole split into parts, labels inside a part only
  when they fit, a legend for every chart with more than one series, hairline rules, no dashed lines.
- **Readable when GitHub shrinks it.** Figures are 960 pixels wide; text that matters is 15 pixels or more.

## Regenerating

```
python scripts/make_figures.py                 # every figure into docs/figures/
python scripts/make_figures.py --only hero     # one of: hero how chain results scan repos social icon
```
