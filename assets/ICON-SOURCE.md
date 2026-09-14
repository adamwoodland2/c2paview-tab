# Content Credentials "cr" pin icon — source and usage notes

## Files in this directory

| File | What it is |
|---|---|
| `cr-icon.svg` | The official Content Credentials "cr" pin icon, copied **verbatim** (byte-identical) from the C2PA/CAI web-components package. `viewBox="0 0 24 24"`. Two paths: a white pin body (`fill="white"`) and a dark grey (`#222222`) outline + "cr" glyph. No `currentColor`. |
| `cr.ico` | Windows icon built from `cr-icon.svg`; PNG-compressed frames at 16, 20, 24, 32, 40, 48, 64, 128, 256 px, transparent background. |
| `cr-32.png`, `cr-64.png` | 32 px / 64 px renders for README use. |

No separate colour variant of the pin exists in the source repository. The C2PA-designed pin is
monochrome by design (white body, dark glyph); the only other pin files in the same directory
(`alert.svg`, `missing.svg`) are the identical pin with a red/orange status badge composited beside
it, and `info-blue.svg` is an unrelated Adobe Spectrum info-circle icon. None of these were copied.

## Exact source

- Repository: <https://github.com/contentauth/c2pa-js-legacy> (Content Authenticity Initiative / Adobe).
  This is where the `c2pa-wc` web-components package now lives; the current
  `contentauth/c2pa-js` `main` was restructured and no longer contains `c2pa-wc` or any SVG assets.
- Branch/commit: `main` @ `c8c2912e2855c857277c0e1a6535a6db18e13c8e` (2025-11-07, "Bump versions [skip ci]").
- File path: `packages/c2pa-wc/assets/svg/color/info.svg`
- Direct URL: <https://github.com/contentauth/c2pa-js-legacy/blob/c8c2912e2855c857277c0e1a6535a6db18e13c8e/packages/c2pa-wc/assets/svg/color/info.svg>
- Git blob: `f83cb734e8537d68370eefef88054a6583f67f1f`
- SHA-256 of the file (identical for `cr-icon.svg` here): `52e6925a9640c39bc588b0130c03401a5327eb67ad46e57ff644936fa45c95fe`
- Package: `c2pa-wc` v0.14.17. The file is rendered by the `<cai-indicator>` component
  (`packages/c2pa-wc/src/components/Indicator/Indicator.ts`) and as the badge in
  `<cai-thumbnail>`, i.e. it is the icon the official CAI components show as the Content Credentials pin.

## Licence of the source

- Repository licence (`LICENSE` at repo root): **MIT License, "© Copyright 2021 Adobe. All rights reserved."**
- `packages/c2pa-wc/package.json` declares `"license": "MIT"`.
- Source files in the package carry the header: "Copyright 2022 Adobe. All Rights Reserved. NOTICE: Adobe
  permits you to use, modify, and distribute this file in accordance with the terms of the Adobe license
  agreement accompanying it." (the accompanying licence being the MIT `LICENSE`).
- The MIT licence covers the *file* as software. It does **not** grant trademark rights: the pin design
  itself is a trademark of the C2PA (see below). Nothing in the repository (README, CHANGELOG, LICENSE)
  mentions "trademark" or icon guidelines; those come from the C2PA specification and websites.

## Usage rules stated by C2PA / CAI (quoted)

### C2PA User Experience Guidance for Implementers, version 2.2, section 4.1 "Content Credentials Icon"
<https://spec.c2pa.org/specifications/specifications/2.2/ux/UX_Recommendations.html#_content_credentials_icon>

> The icon, whose trademark is owned by C2PA, takes the shape of a pin, a metaphorical representation for
> applying (or "pinning") Content Credentials to an asset. It is also intended as a navigation element to
> reveal more C2PA information. Its proximity to other international attribution symbols, like copyright and
> Creative Commons, imbues the icon with a level of trust and authority.
>
> The design of the Content Credentials icon has been carefully considered and should not be altered or
> modified in any way. Unacceptable modifications include adding a solid interior fill, drop shadow, or
> applying other graphic alterations to the icon. Avoid using an outline-only pin on patterned background or
> images. Do not add a valid status, as the icon alone should already indicate the presence of a valid
> manifest. When adding a secondary mark for cryptographic validation, avoid placing the status indicator
> over the characters, or using other icons that do not convey cryptographic status.

Section 4.2 "L1 Indicators" of the same document adds:

> The C2PA recommends the Content Credentials icon as the default visual display, but does not require it to
> be the L1 indicator. [...] Within a given application, the L1 indicator should appear in a consistent
> position (e.g., as an asset hover overlay; in the top corner of a social media post) and maintain high
> contrast. To avoid spoofing, do not directly overlay the indicator on top of content or embed it directly
> into the pixel content.

### C2PA UX Guidance version 2.0, sections 4.1–4.2 (older wording, still published)
<https://spec.c2pa.org/specifications/specifications/2.0/ux/UX_Recommendations.html#correct-usage-of-the-icon>

> C2PA requires the name "Content Credentials" to be used for provenance-enabled user experiences that follow
> the technical specification. [...] Therefore, implementors of Content Credentials must adhere to the proper
> usage of the Content Credentials name and visual marks to assure that each experience is consistent,
> coherent and cooperative.
>
> The Content Credentials marks may be used in the following ways to provide consistency across the ecosystem:
> - Verifying and displaying Content Credentials on a website or web application
> - Creating and writing Content Credentials to supported file formats
>
> The icon is comprised of two lower-case characters, "cr," which is a truncation of "credentials." The
> characters are contained in an outlined circle with the lower-right corner angled to 90 degrees. [...]
> Its has been carefully considered and should not be altered or modified in any way.
>
> The pin must always be represented in the highest quality possible. It can be reproduced in high contrast
> gray scale values depending on its application.

### C2PA announcement, "Introducing Official Content Credentials Icon" (2023-10-10)
<https://c2pa.org/introducing-official-content-credentials-icon/>

> In keeping with the guiding principles of the C2PA, it is also open source so it can be easily adopted by
> companies or developers into any platform, product, tool or solution.

### Trademark policy
contentcredentials.org and c2pa.org do not host a dedicated "trademark guidelines" page (the obvious URLs
return 404). Both sites' footers link to the trademark policy of the Joint Development Foundation, of which
the C2PA is a project: <https://jointdevelopment.org/policies/trademark-policy/> ("Updated May 10, 2024").
Relevant quotes from that policy:

> A trademark should not be altered or amended in any way. A mark should not be combined with any other
> mark, hyphenated, abbreviated or displayed in parts.

Permitted uses include using marks "to make true factual statements" and "as a link to the home page of the
applicable project". Questions/permission requests: `trademarks@jointdevelopment.org`.

## Practical summary for this project

- Use the pin unmodified (no fill changes, shadows, recolouring beyond high-contrast greyscale, no
  status badge implying "valid").
- Use it to indicate the presence of / open Content Credentials information, which is the use the C2PA
  guidance sanctions for implementers.
- The `.ico`/`.png` here are plain rasterisations of the unaltered SVG on a transparent background.

## How the raster files were produced

`cairosvg` is installed but its native `libcairo-2.dll` is not present on this machine, so the SVG was
rasterised with `@resvg/resvg-js` 2.6.2 (resvg, via Node) at each target size with a transparent background,
then packed into `cr.ico` with Pillow 12 (`bitmap_format="png"`, one pre-rendered frame per size rather than
downscaling). The ICO was re-opened with Pillow to confirm all nine sizes are present and PNG-encoded.
