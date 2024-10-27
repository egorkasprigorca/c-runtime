#!/bin/bash

# Log file path
LOG_FILE="../logfile.log"

# Function to log a message
log_message_to_file() {
    # Get the current date and time in the specified format
    TIMESTAMP=$(date +"%H:%M:%S-%d:%m:%Y")

    # Create the log entry
    echo "$TIMESTAMP - $1" >> "$LOG_FILE"
}

log_message() {
    # Get the current date and time in the specified format
    TIMESTAMP=$(date +"%H:%M:%S-%d:%m:%Y")

    # Create the log entry
    echo "$TIMESTAMP - $1"
}

# Infinite loop to log messages every 5 seconds
while true; do
    log_message "This is a periodic log message."
    log_message_to_file "This is a periodic log message."
    sleep 5  # Sleep for 5 seconds (you can change this interval)
done