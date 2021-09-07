const cluster = require('cluster');
const cpuCount = require('os').cpus().length;

if (cluster.isMaster) {
  console.info(`Running cluster on CPU core : ${cpuCount}`);
  for (let i = 0; i < cpuCount; i += 1) {
    cluster.fork();
  }
  // Listen for dying workers
  cluster.on('exit', (worker) => {
    // Replace the dead worker, 
    console.error(`Worker %d died , ${worker.id}`);
    cluster.fork();
  });
} else {
  // Include Express
  // eslint-disable-next-line global-require
  require('./express-app');
  console.log('Worker %d running!', cluster.worker.id);
}
