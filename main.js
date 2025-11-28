const { app, BrowserWindow } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const net = require('net');

let mainWindow;
let flaskProcess;
const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;
const FLASK_PORT = 5000;
const REACT_DEV_PORT = 3000;

/**
 * Check if a port is available
 */
function isPortAvailable(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', () => resolve(false));
    server.once('listening', () => {
      server.close();
      resolve(true);
    });
    server.listen(port);
  });
}

/**
 * Wait for Flask server to be ready
 */
async function waitForFlask(maxAttempts = 30) {
  for (let i = 0; i < maxAttempts; i++) {
    const available = await isPortAvailable(FLASK_PORT);
    if (!available) {
      console.log('Flask server is ready');
      return true;
    }
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  return false;
}

/**
 * Spawn the Flask backend process
 */
function startFlaskBackend() {
  return new Promise((resolve, reject) => {
    console.log('Starting Flask backend...');

    // Determine the Python executable and backend path
    const venvPython = process.platform === 'win32'
      ? path.join(__dirname, 'src', 'backend', 'venv', 'Scripts', 'python.exe')
      : path.join(__dirname, 'src', 'backend', 'venv', 'bin', 'python');
    const pythonExecutable = venvPython;
    const backendPath = path.join(__dirname, 'src', 'backend', 'app.py');

    // Check if Flask backend exists
    const fs = require('fs');
    if (!fs.existsSync(backendPath)) {
      console.error(`Flask backend not found at: ${backendPath}`);
      reject(new Error('Flask backend not found'));
      return;
    }

    // Spawn Flask process
    flaskProcess = spawn(pythonExecutable, [backendPath], {
      env: {
        ...process.env,
        FLASK_ENV: isDev ? 'development' : 'production',
        PORT: FLASK_PORT.toString()
      },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Log Flask output
    flaskProcess.stdout.on('data', (data) => {
      console.log(`[Flask] ${data.toString().trim()}`);
    });

    flaskProcess.stderr.on('data', (data) => {
      console.error(`[Flask Error] ${data.toString().trim()}`);
    });

    flaskProcess.on('error', (error) => {
      console.error('Failed to start Flask backend:', error);
      reject(error);
    });

    flaskProcess.on('exit', (code) => {
      console.log(`Flask process exited with code ${code}`);
      if (code !== 0 && code !== null) {
        reject(new Error(`Flask exited with code ${code}`));
      }
    });

    // Wait for Flask to be ready
    waitForFlask()
      .then(ready => {
        if (ready) {
          console.log('Flask backend started successfully');
          resolve();
        } else {
          reject(new Error('Flask backend failed to start in time'));
        }
      })
      .catch(reject);
  });
}

/**
 * Create the main application window
 */
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 1024,
    minHeight: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js') // Optional: add if you need IPC
    },
    icon: path.join(__dirname, 'assets', 'icon.png'), // Optional: add your app icon
    show: false // Don't show until ready-to-show event
  });

  // Show window when ready to avoid flickering
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // Load the app
  if (isDev) {
    // Development: load from React dev server
    mainWindow.loadURL(`http://localhost:${REACT_DEV_PORT}`);
    // Open DevTools in development
    mainWindow.webContents.openDevTools();
  } else {
    // Production: load from build folder
    const indexPath = path.join(__dirname, 'build', 'index.html');
    mainWindow.loadFile(indexPath);
  }

  // Handle window events
  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  mainWindow.on('unresponsive', () => {
    console.error('Window became unresponsive');
  });

  mainWindow.webContents.on('crashed', () => {
    console.error('Window crashed');
  });

  // Handle external links
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    // Open external links in default browser
    require('electron').shell.openExternal(url);
    return { action: 'deny' };
  });
}

/**
 * Cleanup function to kill Flask process
 */
function cleanup() {
  console.log('Cleaning up...');

  if (flaskProcess) {
    console.log('Terminating Flask backend...');

    // Try graceful shutdown first
    flaskProcess.kill('SIGTERM');

    // Force kill after 5 seconds if still running
    setTimeout(() => {
      if (flaskProcess && !flaskProcess.killed) {
        console.log('Force killing Flask backend...');
        flaskProcess.kill('SIGKILL');
      }
    }, 5000);
  }
}

/**
 * Application initialization
 */
async function initializeApp() {
  try {
    // Start Flask backend first
    await startFlaskBackend();

    // Create the main window
    createWindow();
  } catch (error) {
    console.error('Failed to initialize application:', error);
    app.quit();
  }
}

// App event handlers
app.whenReady().then(initializeApp);

// Quit when all windows are closed
app.on('window-all-closed', () => {
  // On macOS, apps typically stay open until explicitly quit
  if (process.platform !== 'darwin') {
    cleanup();
    app.quit();
  }
});

app.on('activate', () => {
  // On macOS, re-create window when dock icon is clicked
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// Cleanup on app quit
app.on('before-quit', (event) => {
  cleanup();
});

app.on('will-quit', () => {
  cleanup();
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught exception:', error);
  cleanup();
  app.quit();
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled rejection at:', promise, 'reason:', reason);
});

// Graceful shutdown on SIGTERM/SIGINT
process.on('SIGTERM', () => {
  console.log('SIGTERM received');
  cleanup();
  app.quit();
});

process.on('SIGINT', () => {
  console.log('SIGINT received');
  cleanup();
  app.quit();
});
