Cyber Range as a Service DLP Simulation Tool

Overview
This project is a graphical Python application that demonstrates how a Data Loss Prevention system works. It simulates real world scenarios where users attempt to send sensitive data outside an organization and the system detects and prevents the leakage.

The application follows a complete security workflow:
Attack Simulation to Detection to Alert Generation to Response Action

Objectives
The main goal of this project is to simulate data leakage scenarios and build a system that can identify sensitive information and take appropriate action. It also helps in understanding how security operations teams monitor and respond to such incidents.

Features

Attack Simulation
The system allows users to simulate different types of data exfiltration such as sending messages, uploading files, and copying sensitive content.

Detection Engine
The application uses pattern matching and context based logic to detect sensitive data. It identifies credit card numbers, email addresses, passwords, and confidential keywords.

Alert System
Whenever sensitive data is detected, the system generates an alert with severity levels such as low, medium, and high.

User Roles
Different user roles such as admin, employee, and guest are supported. Detection severity can vary depending on the role.

Response Actions
The system provides options to block, mask, or allow the data. Masking hides sensitive parts of the data before allowing it.

Logging
All activities are recorded with timestamp, user role, action performed, detection result, and response taken.

Analytics
The project includes basic charts to visualize total requests, violations, and severity distribution.

MITRE Mapping
The project relates data exfiltration activities to standard attack techniques such as data exfiltration and exfiltration over web.

Technologies Used
Python
Tkinter for graphical interface
Regular expressions for detection
Matplotlib for charts
Datetime for logging

Project Structure

main.py contains the complete application
README.md contains project documentation
requirements.txt lists required libraries
sample files folder contains test inputs

Installation

Clone the repository
git clone https://github.com/your-username/DLP-Cyber-Range.git

Move into the project folder
cd DLP-Cyber-Range

Install required libraries
pip install matplotlib

Run the application
python main.py

Sample Inputs

Credit card example
4111-1111-1111-1111

Password example
My password is admin123

Email example
user@example.com

Confidential data example
salary details of employees

Working Process

The user selects an attack type and enters data
The system scans the input using detection rules
If sensitive data is found, an alert is generated
The user selects a response action
The event is logged and displayed

Future Improvements

Add advanced detection using machine learning
Store logs in a database
Convert the application into a web based tool
Improve user interface design

Learning Outcomes

Understanding of data loss prevention systems
Knowledge of cyber range simulation
Experience in building detection logic using Python
Better understanding of security monitoring concepts

Disclaimer
This project is developed for academic purposes only. It does not interact with real systems or networks.

Author
Your Name
