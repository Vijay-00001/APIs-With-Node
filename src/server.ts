import cluster from 'cluster';
import os from 'os';
import app from './app'; // Your express app
import http from 'http';

if (cluster.isMaster) {
   const numCPUs = os.cpus().length;

   console.log(`Master process is running with PID: ${process.pid}`);

   // Fork workers.
   for (let i = 0; i < numCPUs; i++) {
      cluster.fork();
   }

   cluster.on('exit', (worker, code, signal) => {
      console.log(`Worker ${worker.process.pid} died`);
      cluster.fork(); // Restart the worker
   });
} else {
   // Workers can share the TCP connection
   const server = http.createServer(app);

   server.listen(process.env.PORT || 5000, () => {
      console.log(`Worker process started with PID: ${process.pid}`);
   });
}
