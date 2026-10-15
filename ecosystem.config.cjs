module.exports = {
  apps: [
    {
      name: 'patchworkos',
      script: 'server.js',
      // Run single instance fork mode because better-sqlite3 manages SQLite file locks in-process
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      env: {
        NODE_ENV: 'production',
        PORT: 3000
      }
    }
  ]
};
