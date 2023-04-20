

int LED_PIN = 2;

// currentState defines which state the device is in (ONLY FOR LEDS):
// 0  -> disconnected
// 1  -> connected but not authenticated
// 2  -> connected and authenticated
int currentState = 0;

// Start Signal -> 10 fast blinks
void start_signal() {

  pinMode(LED_PIN, OUTPUT);
  state_change_signal();
}


// Waiting for connection signal -> blinking once each 2 seconds
void waiting_for_connection_signal(){
  if (currentState != 0){
    disconnected_signal();
  }
  digitalWrite(LED_PIN, HIGH);
  delay(800);
  digitalWrite(LED_PIN, LOW);
  delay(2000);
}

// Connected signal -> 10 fast blinks, and then blinking on each second
void connected_signal(){
  if (currentState == 0){
    state_change_signal();
    currentState = 1;
  }
  digitalWrite(LED_PIN, HIGH);
  delay(500);
  digitalWrite(LED_PIN, LOW);
  delay(500);
}

// Disconnected signal -> 10 fast blinks, and then keeping LED OFF
void disconnected_signal(){
  if (currentState >= 1) {
    state_change_signal();
    currentState = 0;
  }
}

// Starting authentication process signal -> 5 bursts of 3 fast blinks
void starting_auth_signal(){
  for(int i=0; i<5; i++){
    for (int j=0; j<3; j++){
      digitalWrite(LED_PIN, HIGH);
      delay(100);
      digitalWrite(LED_PIN, LOW);
      delay(100);
    }
    delay(1000);
  }
}

// Authentication process finished successfully -> 3 bursts of 5 fast blinks
void authenticated_signal(){
  if (currentState != 2){
    for(int i=0; i<3; i++){
      for (int j=0; j<5; j++){
        digitalWrite(LED_PIN, HIGH);
        delay(100);
        digitalWrite(LED_PIN, LOW);
        delay(100);
      }
      delay(2000);
    }
    currentState = 2;
  }

  digitalWrite(LED_PIN, HIGH);
}

// When the current state changes -> 10 fast blinks
void state_change_signal(){
  for(int i=0; i<10; i++){
    digitalWrite(LED_PIN, HIGH);
    delay(100);
    digitalWrite(LED_PIN, LOW);
    delay(100);
  }
}
