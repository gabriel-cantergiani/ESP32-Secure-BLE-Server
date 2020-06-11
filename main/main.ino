
// Aqui é o arquivo central. Ele só instancia e chama funções e variáveis dos outros arquivos

bool isConnected = false;
bool isAuthenticated = false;

void setup() {
  
  // Initialize serial communication
  Serial.begin(115200);
  
  // Initialization delay
  delay(5000);

  Serial.println(">> Starting setup...");
  
  // Start Device LED signal
  start_signal();
  
  // Initialize BLE Server
  Serial.println(">> Initializing BLE Server...");
  initializeServer();
}

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
