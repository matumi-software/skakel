# Skakel brand

Skakel is the link between apps on a local network. *Skakel* is Afrikaans for a link in a chain, and
to connect. It is a Matumi Software product and belongs to the same family as
[Koppel](https://github.com/matumi-software/koppel): the same canopy green on warm stone, the same
type and the same stroke weights. Koppel's design system
(`resources/design-system` in the Koppel repo) is the reference for everything not covered here.

## Mark

The mark is a vertical chain link drawn as a figure eight. It is one stroke with a slit where the
strand passes under itself, which makes it read as an S, an infinity sign and a chain link at the
same time.

- `assets/Logos/skakel-mark.svg`: canopy `#2A6B4E`, for light grounds.
- `assets/Logos/skakel-mark-on-dark.svg`: canopy `#549572`, for dark grounds.
- `assets/Logos/skakel-app-icon.svg`: the mark in paper `#FBF9F4` on a canopy `#2A6B4E` tile with a
  14/64 corner radius, the same tile as Koppel's app icon.
- `skakel-app-icon-128.png` is the NuGet package icon. `skakel-app-icon-512.png` and the
  `skakel-mark*-512.png` files are for anywhere an image is needed.
- Stroke width is 10 on a 64 grid with butt caps. Keep the slit open: never round the caps or close
  the gap.
- Clear space is half the mark's width on every side. Do not draw it below 16px.

## Wordmark

"skakel", always lowercase like the other Matumi Software wordmarks, set in Instrument Sans 600 beside the mark, with the mark's height matched to the cap
height plus ascender. There is no outlined wordmark file; set it in type.

## Colour

| Token | Light | Dark | Use |
|---|---|---|---|
| canopy | `#2A6B4E` | `#549572` | The mark and the one accent |
| river | `#2F6F74` | `#5FA0A6` | Skakel's lead colour in graphics, where Koppel leads with canopy |
| page | `#FBF9F4` | `#161512` | Backgrounds, never blue-black |
| ink | `#1C1B18` | `#EDEAE0` | Text |

## Type

Instrument Sans for text, JetBrains Mono for code, paths and identifiers. Sentence case, no
exclamation marks, no emoji.

## Social preview

`assets/Social/skakel-social-preview.png` is the 1280x640 image for the GitHub repo
(Settings > General > Social preview) and for link cards. Its source is
`skakel-social-preview.html` next to it: open it in a browser at 1280x640 and screenshot the card to
regenerate it.
