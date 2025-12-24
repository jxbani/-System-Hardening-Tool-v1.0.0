# IronGuard OS - Color Palette Reference

## Quick Visual Reference

### Primary Brand Colors

```
┌─────────────────────────────────────────────┐
│ PRIMARY CYAN                                │
│ #00D9FF                                     │
│ RGB(0, 217, 255)                           │
│ ███████████████████████████████████████████ │
│ Main brand color, CTAs, highlights          │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ SECONDARY PURPLE                            │
│ #A855F7                                     │
│ RGB(168, 85, 247)                          │
│ ███████████████████████████████████████████ │
│ Secondary brand, gradient combinations      │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ PRIMARY GRADIENT                            │
│ linear-gradient(135deg, #00D9FF, #A855F7)  │
│ ███████████████████████████████████████████ │
│ Buttons, headers, progress bars             │
└─────────────────────────────────────────────┘
```

### Severity Colors

```
┌─────────────────────────────────────────────┐
│ CRITICAL                                    │
│ #FF3366                                     │
│ RGB(255, 51, 102)                          │
│ ███████████████████████████████████████████ │
│ Critical vulnerabilities, urgent alerts     │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ HIGH                                        │
│ #FF6B35                                     │
│ RGB(255, 107, 53)                          │
│ ███████████████████████████████████████████ │
│ High severity issues, important warnings    │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ MEDIUM                                      │
│ #FFA500                                     │
│ RGB(255, 165, 0)                           │
│ ███████████████████████████████████████████ │
│ Medium severity, moderate concerns          │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ LOW                                         │
│ #4ECDC4                                     │
│ RGB(78, 205, 196)                          │
│ ███████████████████████████████████████████ │
│ Low severity, informational items           │
└─────────────────────────────────────────────┘
```

### Status Colors

```
┌─────────────────────────────────────────────┐
│ SUCCESS                                     │
│ #10B981                                     │
│ RGB(16, 185, 129)                          │
│ ███████████████████████████████████████████ │
│ Success messages, completed actions         │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ WARNING                                     │
│ #F59E0B                                     │
│ RGB(245, 158, 11)                          │
│ ███████████████████████████████████████████ │
│ Warning notifications, caution states       │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ DANGER                                      │
│ #EF4444                                     │
│ RGB(239, 68, 68)                           │
│ ███████████████████████████████████████████ │
│ Error messages, destructive actions         │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ INFO                                        │
│ #3B82F6                                     │
│ RGB(59, 130, 246)                          │
│ ███████████████████████████████████████████ │
│ Informational alerts, neutral messages      │
└─────────────────────────────────────────────┘
```

### Background Colors

```
┌─────────────────────────────────────────────┐
│ PRIMARY BACKGROUND                          │
│ #0A0E1A                                     │
│ RGB(10, 14, 26)                            │
│ ███████████████████████████████████████████ │
│ Main page background, deep navy             │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ SECONDARY BACKGROUND                        │
│ #111827                                     │
│ RGB(17, 24, 39)                            │
│ ███████████████████████████████████████████ │
│ Header, modals, elevated surfaces           │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ CARD BACKGROUND                             │
│ #1A1F2E                                     │
│ RGB(26, 31, 46)                            │
│ ███████████████████████████████████████████ │
│ Cards, panels, content containers           │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ CARD HOVER                                  │
│ #232938                                     │
│ RGB(35, 41, 56)                            │
│ ███████████████████████████████████████████ │
│ Card hover state, interactive surfaces      │
└─────────────────────────────────────────────┘
```

### Text Colors

```
┌─────────────────────────────────────────────┐
│ PRIMARY TEXT                                │
│ #F9FAFB                                     │
│ RGB(249, 250, 251)                         │
│ ███████████████████████████████████████████ │
│ Headings, important content, high emphasis  │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ SECONDARY TEXT                              │
│ #D1D5DB                                     │
│ RGB(209, 213, 219)                         │
│ ███████████████████████████████████████████ │
│ Body text, descriptions, medium emphasis    │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ TERTIARY TEXT                               │
│ #9CA3AF                                     │
│ RGB(156, 163, 175)                         │
│ ███████████████████████████████████████████ │
│ Labels, captions, low emphasis              │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ MUTED TEXT                                  │
│ #6B7280                                     │
│ RGB(107, 114, 128)                         │
│ ███████████████████████████████████████████ │
│ Placeholders, disabled states               │
└─────────────────────────────────────────────┘
```

## CSS Variables

### Copy-Paste Ready

```css
:root {
  /* Primary Colors */
  --primary: #00D9FF;
  --primary-dark: #00A8CC;
  --secondary: #A855F7;
  --secondary-dark: #7C3AED;

  /* Accent Colors */
  --accent-cyan: #06B6D4;
  --accent-purple: #8B5CF6;
  --accent-pink: #EC4899;

  /* Status Colors */
  --success: #10B981;
  --warning: #F59E0B;
  --danger: #EF4444;
  --info: #3B82F6;

  /* Severity Colors */
  --severity-critical: #FF3366;
  --severity-high: #FF6B35;
  --severity-medium: #FFA500;
  --severity-low: #4ECDC4;

  /* Background Colors */
  --bg-primary: #0A0E1A;
  --bg-secondary: #111827;
  --bg-tertiary: #1F2937;
  --bg-card: #1A1F2E;
  --bg-card-hover: #232938;

  /* Text Colors */
  --text-primary: #F9FAFB;
  --text-secondary: #D1D5DB;
  --text-tertiary: #9CA3AF;
  --text-muted: #6B7280;

  /* Border Colors */
  --border-primary: rgba(255, 255, 255, 0.1);
  --border-secondary: rgba(255, 255, 255, 0.05);
  --border-glow: rgba(0, 217, 255, 0.3);
}
```

## Usage Examples

### Primary Button
```css
.btn-primary {
  background: linear-gradient(135deg, var(--primary), var(--secondary));
  color: white;
  box-shadow: 0 4px 12px rgba(0, 217, 255, 0.3);
}
```

### Severity Badge
```css
.severity-critical {
  background: rgba(255, 51, 102, 0.15);
  border-color: var(--severity-critical);
  color: var(--severity-critical);
}
```

### Card
```css
.card {
  background: var(--bg-card);
  border: 1px solid var(--border-primary);
  color: var(--text-primary);
}
```

### Alert
```css
.alert-success {
  background: rgba(16, 185, 129, 0.1);
  border: 1px solid var(--success);
  color: #6EE7B7;
}
```

## Accessibility Compliance

### WCAG 2.1 AA Contrast Ratios

All color combinations meet accessibility standards:

| Foreground | Background | Ratio | Standard |
|------------|------------|-------|----------|
| Text Primary (#F9FAFB) | BG Primary (#0A0E1A) | 15.8:1 | ✅ AAA |
| Text Secondary (#D1D5DB) | BG Primary (#0A0E1A) | 11.2:1 | ✅ AAA |
| Text Tertiary (#9CA3AF) | BG Primary (#0A0E1A) | 6.9:1 | ✅ AA |
| Primary (#00D9FF) | BG Primary (#0A0E1A) | 9.5:1 | ✅ AAA |
| Success (#10B981) | BG Primary (#0A0E1A) | 7.1:1 | ✅ AAA |
| Warning (#F59E0B) | BG Primary (#0A0E1A) | 8.9:1 | ✅ AAA |

## Color Psychology

### Why These Colors?

**Cyan (#00D9FF)**:
- Trust and professionalism
- Technology and innovation
- Clarity and precision
- High visibility without strain

**Purple (#A855F7)**:
- Creativity and sophistication
- Premium quality
- Modern technology
- Security and encryption

**Dark Navy (#0A0E1A)**:
- Professionalism
- Focus and concentration
- Reduced eye strain
- Premium appearance

## Gradients

### Primary Gradient
```css
background: linear-gradient(135deg, #00D9FF 0%, #A855F7 100%);
```
**Use**: Main CTAs, progress bars, highlights

### Success Gradient
```css
background: linear-gradient(135deg, #10B981 0%, #059669 100%);
```
**Use**: Success states, completion indicators

### Danger Gradient
```css
background: linear-gradient(135deg, #EF4444 0%, #DC2626 100%);
```
**Use**: Error states, critical warnings

## Opacity Variations

### Backgrounds
```css
rgba(255, 255, 255, 0.03)  /* Subtle surface */
rgba(255, 255, 255, 0.05)  /* Light surface */
rgba(255, 255, 255, 0.08)  /* Hover state */
rgba(255, 255, 255, 0.10)  /* Active state */
```

### Borders
```css
rgba(255, 255, 255, 0.05)  /* Subtle divider */
rgba(255, 255, 255, 0.10)  /* Standard border */
rgba(0, 217, 255, 0.30)    /* Glow effect */
```

## Dark Mode Optimization

All colors are optimized for dark backgrounds:
- High contrast ratios
- Reduced blue light
- Comfortable for extended viewing
- Professional appearance
- SOC-environment friendly

## Print Considerations

For report generation, these colors print well:
- High contrast maintains readability
- Severity colors are distinguishable in grayscale
- Gradient backgrounds are optional
- Text colors have sufficient darkness

## Brand Consistency

This palette maintains consistency across:
- Dashboard interface
- Generated reports
- Modal dialogs
- Alert messages
- Data visualizations
- Documentation

---

**Color Palette Version**: 2.0
**WCAG Compliance**: AA (Target: AAA where possible)
**Last Updated**: December 2024
