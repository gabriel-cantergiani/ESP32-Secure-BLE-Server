/*
*
*   MAIN MODULE
*   
*   Created by: Gabriel Cantergiani, June 2020
*/


bool isConnected = false;
bool isAuthenticated = false;

void setup() {
  
  // Initialize serial communication
  Serial.begin(115200);
  
  // Initialization delay
  delay(5000);

  Serial.println(">> [MAIN] Starting setup...");
  
  // Start Device LED signal
  start_signal();
  
  // Initialize BLE Server
  Serial.println(">> [MAIN] Initializing BLE Server...");
  initializeServer();
}

// Loop, calls LED signals to indicate current state of connectivity
void loop() {
  
  while(!isConnected){
    waiting_for_connection_signal(); 
  }
  
  if(!isAuthenticated) {
    connected_signal();
  }
  else {
    authenticated_signal();
  }

}
