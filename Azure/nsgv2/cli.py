"""
Command-line interface for NSGv2 - Optimized NSG flow logs query tool
"""

import argparse
import sys
from datetime import datetime
from .direct_query import query_ip_traffic

def main():
    """
    Main entry point for the NSGv2 command-line tool
    """
    parser = argparse.ArgumentParser(description='Optimized NSG flow logs query tool')
    parser.add_argument('ip', help='Target IP address to query')
    parser.add_argument('--hours', '-t', type=int, default=24, 
                        help='Time range in hours (default: 24)')
    
    args = parser.parse_args()
    
    try:
        # Show start time
        start_time = datetime.now()
        print(f"Started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Execute the query
        results = query_ip_traffic(args.ip, args.hours)
        
        # Show end time and duration
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        print(f"Completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total duration: {duration:.1f} seconds")
        
        # Return success or failure code
        if results:
            total_records = sum(len(data['results']) for data in results.values())
            if total_records > 0:
                return 0  # Success
        return 1  # No results found
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 130
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
