// src/utils/networkUtils.ts
import { exec } from 'child_process';

export const checkNetworkConnection = (): Promise<boolean> => {
   return new Promise(resolve => {
      exec('ping -c 1 google.com', error => {
         resolve(!error); // Resolve true if no error (connected), else false
      });
   });
};
