# IronGuard OS - Modern Security Dashboard

![Version](https://img.shields.io/badge/version-2.0-blue.svg)
![React](https://img.shields.io/badge/react-18.2.0-61dafb.svg)
![Status](https://img.shields.io/badge/status-production%20ready-success.svg)

A stunning, modern cybersecurity dashboard with real-time security scanning, vulnerability management, and comprehensive reporting capabilities.

## Features

### Core Functionality

- **Real-Time Security Scanning**: Comprehensive system vulnerability detection
- **Backend Health Monitoring**: Live connection status with visual indicators
- **Vulnerability Management**: Detailed findings with severity classification
- **Automated Remediation**: One-click security fixes with step-by-step guidance
- **Multi-Format Reporting**: Export in PDF, Excel, CSV, Word, Markdown, HTML, JSON
- **Compliance Scoring**: Real-time security posture assessment

### UI/UX Highlights

- **Modern Dark Theme**: Cybersecurity-focused design with cyan/purple accents
- **Responsive Design**: Optimized for mobile, tablet, and desktop
- **Accessibility Compliant**: WCAG 2.1 AA standards
- **Smooth Animations**: Professional transitions and micro-interactions
- **Real-Time Updates**: Live scan progress and status indicators
- **Advanced Filtering**: Search, sort, and filter vulnerabilities
- **Bulk Operations**: Select and remediate multiple issues

## Quick Start

### Prerequisites

- Node.js 14+ and npm
- Backend server running on `http://localhost:5000`

### Installation

```bash
# Navigate to frontend directory
cd src/frontend

# Install dependencies
npm install

# Start development server
npm start
```

The dashboard will open at `http://localhost:3000`

### Backend Integration

Ensure the backend API is running:

```bash
# In the backend directory
cd src/backend
python app.py
```

The frontend expects the backend at `http://localhost:5000/api`

## Architecture

### Component Structure

```
src/
├── components/
│   ├── ModernDashboard.js           # Main dashboard container
│   ├── ModernDashboard.css          # Dashboard styling
│   ├── ModernScanResults.js         # Vulnerability results display
│   ├── ModernScanResults.css        # Results table styling
│   ├── ModernVulnerabilityModal.js  # Detailed vulnerability view
│   └── ModernVulnerabilityModal.css # Modal styling
├── api/
│   └── client.js                    # Backend API integration
├── App.js                           # Root component
└── App.css                          # Global styles
```

### Key Components

#### ModernDashboard
The main container component that orchestrates:
- Backend health checks
- System information display
- Security scan execution
- Statistics visualization
- Report generation
- Results presentation

#### ModernScanResults
Handles vulnerability display and management:
- Tabular data presentation
- Severity-based filtering
- Search functionality
- Bulk selection
- Remediation actions

#### ModernVulnerabilityModal
Provides detailed vulnerability information:
- Three-tab interface (Overview, Remediation, Details)
- Step-by-step fix instructions
- Code blocks with copy functionality
- Risk assessment
- External references

## API Integration

### Available Endpoints

The dashboard integrates with these backend APIs:

```javascript
// System Information
GET /api/system-info

// Health Check
GET /api/health

// Security Scan
POST /api/scan

// Report Generation
POST /api/report
{
  format: 'pdf' | 'excel' | 'csv' | 'docx' | 'markdown' | 'html' | 'json',
  title: 'Report Title',
  scan_results: {...}
}

// Apply Hardening
POST /api/harden
{
  rules: ['rule_id_1', 'rule_id_2']
}
```

## Design System

### Color Palette

**Primary Colors**:
- Cyan: `#00D9FF` - Primary brand color
- Purple: `#A855F7` - Secondary brand color

**Severity Colors**:
- Critical: `#FF3366`
- High: `#FF6B35`
- Medium: `#FFA500`
- Low: `#4ECDC4`

**Status Colors**:
- Success: `#10B981`
- Warning: `#F59E0B`
- Danger: `#EF4444`
- Info: `#3B82F6`

**Backgrounds**:
- Primary: `#0A0E1A` - Deep navy
- Secondary: `#111827` - Dark gray
- Card: `#1A1F2E` - Slate

### Typography

**Font Stack**:
```css
-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell'
```

**Monospace** (for code):
```css
'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono'
```

### Spacing

Based on 4px increments:
- xs: 0.5rem (8px)
- sm: 1rem (16px)
- md: 1.5rem (24px)
- lg: 2rem (32px)
- xl: 3rem (48px)

## User Guide

### Running a Security Scan

1. Ensure backend is connected (green indicator in header)
2. Click "Start Security Scan" button
3. Monitor progress bar (typically 10-30 seconds)
4. Review findings in the results table

### Managing Vulnerabilities

1. **Filter by Severity**: Click severity chips (Critical, High, Medium, Low)
2. **Search**: Use search bar to find specific issues
3. **View Details**: Click "View Details" on any vulnerability
4. **Apply Fixes**: Select vulnerabilities and click "Apply Selected Fixes"

### Generating Reports

1. Run a security scan first
2. Scroll to "Generate Security Report" section
3. Select desired format (PDF, Excel, CSV, etc.)
4. Click "Generate Report"
5. Report downloads automatically

### Understanding Severity Levels

- **Critical**: Immediate action required, severe security risk
- **High**: Should be addressed soon, significant vulnerability
- **Medium**: Address in next maintenance window
- **Low**: Minor issue or improvement opportunity

## Customization

### Theming

To customize colors, edit CSS variables in component files:

```css
:root {
  --primary: #00D9FF;
  --secondary: #A855F7;
  /* Add your custom colors */
}
```

### Adding Features

1. Create new component in `src/components/`
2. Add corresponding CSS file
3. Import and use in `ModernDashboard.js`
4. Update API client if backend integration needed

## Performance

### Optimization Features

- CSS animations use `transform` and `opacity` for hardware acceleration
- Lazy loading for off-screen content
- Debounced search and filter operations
- Efficient re-renders with React best practices
- Minimal bundle size with tree-shaking

### Best Practices

- Keep components modular and focused
- Use React.memo for expensive components
- Avoid inline function definitions in renders
- Implement proper loading states
- Handle errors gracefully

## Accessibility

### Features

- **Keyboard Navigation**: Full keyboard support
- **Screen Readers**: ARIA labels and semantic HTML
- **Focus Management**: Clear focus indicators
- **Color Contrast**: WCAG 2.1 AA compliant
- **Reduced Motion**: Respects user preferences

### Testing

```bash
# Install accessibility testing tools
npm install -D @axe-core/react

# Run accessibility audits
npm run test
```

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Troubleshooting

### Backend Connection Issues

**Problem**: Red "Offline" status indicator

**Solutions**:
1. Verify backend is running: `http://localhost:5000/api/health`
2. Check for CORS issues in browser console
3. Ensure proxy is configured in `package.json`

### Scan Not Starting

**Problem**: Scan button disabled or no response

**Solutions**:
1. Check backend connection status
2. Review browser console for errors
3. Verify API endpoint is accessible
4. Check network tab for failed requests

### Report Generation Fails

**Problem**: Report doesn't download

**Solutions**:
1. Ensure scan has been run first
2. Check browser pop-up blocker settings
3. Verify backend has necessary dependencies (WeasyPrint, etc.)
4. Review browser downloads folder

### Styling Issues

**Problem**: Components not displaying correctly

**Solutions**:
1. Clear browser cache
2. Verify all CSS files are imported
3. Check for CSS variable support in browser
4. Inspect element for conflicting styles

## Development

### Code Structure

- **Components**: Functional React components with hooks
- **Styling**: CSS modules with BEM-inspired naming
- **State Management**: React useState and useEffect hooks
- **API Calls**: Centralized in `api/client.js`

### Adding New Features

1. Design component interface
2. Create component file
3. Write corresponding CSS
4. Add to parent component
5. Test functionality
6. Update documentation

### Testing

```bash
# Run all tests
npm test

# Run specific test file
npm test -- ModernDashboard.test.js

# Coverage report
npm test -- --coverage
```

## Deployment

### Production Build

```bash
# Create optimized production build
npm run build

# Output directory: build/
```

### Environment Variables

Create `.env.production`:

```
REACT_APP_API_URL=https://your-backend-api.com/api
REACT_APP_VERSION=2.0
```

### Hosting Options

- **Static Hosting**: Netlify, Vercel, GitHub Pages
- **Container**: Docker with Nginx
- **CDN**: CloudFront, Cloudflare Pages

## Security Considerations

### Best Practices

1. **API Communication**: Always use HTTPS in production
2. **Input Validation**: Sanitize all user inputs
3. **XSS Prevention**: React escapes values by default
4. **CSRF Protection**: Implement tokens for state-changing operations
5. **Content Security Policy**: Configure CSP headers

### Sensitive Data

- Never commit API keys or secrets
- Use environment variables for configuration
- Sanitize error messages in production
- Implement proper authentication/authorization

## Contributing

### Guidelines

1. Follow existing code style
2. Write clear commit messages
3. Add tests for new features
4. Update documentation
5. Ensure accessibility compliance

### Pull Request Process

1. Fork the repository
2. Create feature branch
3. Make changes
4. Test thoroughly
5. Submit PR with description

## License

This project is part of the IronGuard OS Security Tool.

## Support

For issues, questions, or contributions:
- Review documentation
- Check troubleshooting guide
- Examine source code comments
- Review API integration guide

## Changelog

### Version 2.0 (Current)
- Complete UI redesign with modern cybersecurity theme
- Enhanced vulnerability detail views
- Improved responsive design
- Advanced filtering and search
- Multi-format report generation
- Real-time status indicators
- Accessibility improvements
- Performance optimizations

### Version 1.0
- Initial release
- Basic scanning functionality
- Simple vulnerability display
- PDF report generation

---

**Built with React** | **Designed for Security Professionals** | **Production Ready**
