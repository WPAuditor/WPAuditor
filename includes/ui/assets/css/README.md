# WPAuditor CSS architecture

Styles load in this order:

1. `tokens.css` defines shared visual values.
2. `../wpa.css` contains existing admin layouts and page styles.
3. `components.css` defines reusable UI components.
4. `../../theme/wpa-theme.css` contains theme-specific layout overrides.

## Component naming

Use a component base class with a semantic modifier:

```html
<span class="wpa-status-badge wpa-status-badge--success">Active</span>
<span class="wpa-severity-badge wpa-severity-badge--critical">Critical</span>
```

- Status badges describe operational state: success, warning, danger, neutral, or info.
- Severity badges describe security severity: critical, high, medium, low, or info.
- Add reusable colors and dimensions to `tokens.css` instead of page selectors.
- Add reusable patterns to `components.css`.
- Keep page selectors in `wpa.css` until they are moved into a dedicated page stylesheet.
- Do not use a page-specific class to style an unrelated page.
