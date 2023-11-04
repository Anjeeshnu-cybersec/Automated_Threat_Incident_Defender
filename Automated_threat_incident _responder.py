# This code is created by Anjeeshnu Banerjee 
# this is gaurded by Gnu v3 lisence for copy right 
# you can find comment after each line of code to help understand what its doing and yeah its also for my future use soo i dont forget what i have written 


import time  # Import the time module to add time-based functionality


# Import the skfuzzy library for fuzzy logic
import skfuzzy as fuzz
from skfuzzy import control as ctrl

# Create Antecedent (input) and Consequent (output) variables for DDoS detection
traffic_rate = ctrl.Antecedent(universe=[0, 100], label='Traffic Rate')  # Define input variable: traffic rate
packet_size = ctrl.Antecedent(universe=[0, 1500], label='Average Packet Size')  # Define input variable: packet size
ddos_detection = ctrl.Consequent(universe=[0, 100], label='DDoS Detection')  # Define output variable: DDoS detection

# Create Antecedent (input) and Consequent (output) variables for malware detection
packet_count = ctrl.Antecedent(universe=[0, 1000], label='Packet Count')  # Define input variable: packet count
payload_size = ctrl.Antecedent(universe=[0, 2000], label='Payload Size')  # Define input variable: payload size
malware_detection = ctrl.Consequent(universe=[0, 100], label='Malware Detection')  # Define output variable: malware detection

# Define membership functions for the input and output variables
traffic_rate.automf(3)  # Create 3 fuzzy membership functions for traffic rate
packet_size.automf(3)  # Create 3 fuzzy membership functions for packet size
packet_count.automf(3)  # Create 3 fuzzy membership functions for packet count
payload_size.automf(3)  # Create 3 fuzzy membership functions for payload size
ddos_detection.automf(3)  # Create 3 fuzzy membership functions for DDoS detection
malware_detection.automf(3)  # Create 3 fuzzy membership functions for malware detection

# Define fuzzy rules for DDoS detection
rule1 = ctrl.Rule(traffic_rate['good'] & packet_size['small'], ddos_detection['low'])  # Define a fuzzy rule for DDoS detection
rule2 = ctrl.Rule(traffic_rate['average'] & packet_size['medium'], ddos_detection['medium'])  # Define another fuzzy rule
rule3 = ctrl.Rule(traffic_rate['poor'] & packet_size['large'], ddos_detection['high'])  # Define another fuzzy rule

# Define fuzzy rules for malware detection
rule4 = ctrl.Rule(packet_count['good'] & payload_size['small'], malware_detection['low'])  # Define a fuzzy rule for malware detection
rule5 = ctrl.Rule(packet_count['average'] & payload_size['medium'], malware_detection['medium'])  # Define another fuzzy rule
rule6 = ctrl.Rule(packet_count['poor'] & payload_size['large'], malware_detection['high'])  # Define another fuzzy rule

# Create control systems
ddos_ctrl = ctrl.ControlSystem([rule1, rule2, rule3])  # Create a control system for DDoS detection
malware_ctrl = ctrl.ControlSystem([rule4, rule5, rule6])  # Create a control system for malware detection

# Create the simulators
ddos_sim = ctrl.ControlSystemSimulation(ddos_ctrl)  # Create a simulator for DDoS control system
malware_sim = ctrl.ControlSystemSimulation(malware_ctrl)  # Create a simulator for malware control system

# Function to simulate traffic (replace with actual data)
def simulate_traffic():
    return 50, 1000  # Simulated traffic rate and packet size

# Function to simulate packet data (replace with actual data)
def simulate_packet_data():
    return 300, 1500  # Simulated packet count and payload size

# Function to detect DDoS attacks using fuzzy logic
def detect_ddos_attack():
    traffic_rate, packet_size = simulate_traffic()  # Simulate traffic data
    ddos_sim.input['Traffic Rate'] = traffic_rate  # Set input for traffic rate
    ddos_sim.input['Average Packet Size'] = packet_size  # Set input for packet size
    ddos_sim.compute()  # Perform fuzzy inference
    ddos_score = ddos_sim.output['DDoS Detection']  # Get the DDoS detection score
    return ddos_score > 50  # Adjust the threshold to classify an incident as a DDoS attack

# Function to detect malware using fuzzy logic
def detect_malware():
    packet_count, payload_size = simulate_packet_data()  # Simulate packet data
    malware_sim.input['Packet Count'] = packet_count  # Set input for packet count
    malware_sim.input['Payload Size'] = payload_size  # Set input for payload size
    malware_sim.compute()  # Perform fuzzy inference
    malware_score = malware_sim.output['Malware Detection']  # Get the malware detection score
    return malware_score > 50  # Adjust the threshold to classify an incident as malware

# Main function
def main():
    print("Automated Incident Response System")

    while True:
        if detect_ddos_attack():
            print("DDoS attack detected. Initiating automated response...")
            # Implement your actual response actions here for DDoS attacks
            time.sleep(2)  # Simulate response actions
            print("Automated response to DDoS attack completed.")
        
        if detect_malware():
            print("Malware attack detected. Initiating automated response...")
            # Implement your actual response actions here for malware attacks
            time.sleep(2)  # Simulate response actions
            print("Automated response to malware attack completed.")
        
        time.sleep(10)  # Adjust the sleep duration as needed

if __name__ == "__main__":
    main()
