import time
import logging
import argparse
import signal
import sys
from domain_collector import DomainCollector
from config import COLLECTION_CONFIG

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QueueProcessor:
    def __init__(self, force_shutdown_after=3):
        self.collector = DomainCollector()
        self.shutdown_requested = False
        self.signal_count = 0
        self.force_shutdown_after = force_shutdown_after
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully with forced shutdown"""
        self.signal_count += 1
        logger.info(f"Received signal {signum} (count: {self.signal_count}), initiating graceful shutdown...")
        
        if self.signal_count >= self.force_shutdown_after:
            logger.warning(f"Force shutdown after {self.signal_count} signals!")
            sys.exit(1)
        
        self.shutdown_requested = True
    
    def run(self, max_items=50, max_depth=None, continuous=False):
        """Run the queue processor"""
        if max_depth is None:
            max_depth = COLLECTION_CONFIG['max_depth']
        
        logger.info(f"Starting queue processor with max_items={max_items}, max_depth={max_depth}, continuous={continuous}")
        
        try:
            while not self.shutdown_requested:
                # Get queue statistics
                stats = self.collector.db.get_queue_stats()
                logger.info(f"Queue stats: {stats}")
                
                # Process queue with shutdown check
                self.collector.process_queue(
                    max_items=max_items, 
                    max_depth=max_depth,
                    shutdown_check=lambda: self.shutdown_requested
                )
                
                if not continuous:
                    logger.info("Queue processing completed")
                    break
                
                # Check for shutdown before waiting
                if self.shutdown_requested:
                    logger.info("Shutdown requested, stopping queue processing")
                    break
                
                # Wait before next iteration
                logger.info("Waiting 60 seconds before next queue check...")
                for _ in range(60):
                    if self.shutdown_requested:
                        break
                    time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Queue processor interrupted by user")
        except Exception as e:
            logger.error(f"Queue processor failed: {e}")
        finally:
            logger.info("Cleaning up resources...")
            self.collector.close()
            logger.info("Queue processor shutdown complete")
    
    def add_seed_domains(self, domains, priority=1):
        """Add seed domains to the queue"""
        logger.info(f"Adding {len(domains)} seed domains to queue")
        
        for domain in domains:
            try:
                self.collector.db.add_to_discovery_queue(
                    url=f"http://{domain}",
                    domain_name=domain,
                    source_domain_id=None,
                    depth=0,
                    priority=priority
                )
                logger.info(f"Added {domain} to queue")
            except Exception as e:
                logger.error(f"Error adding {domain} to queue: {e}")


def main():
    """Main function for queue processor"""
    parser = argparse.ArgumentParser(description='Process domain discovery queue')
    parser.add_argument('--max-items', type=int, default=50, help='Maximum items to process per batch')
    parser.add_argument('--max-depth', type=int, default=COLLECTION_CONFIG['max_depth'], help='Maximum crawl depth')
    parser.add_argument('--continuous', action='store_true', help='Run continuously')
    parser.add_argument('--add-seeds', nargs='+', help='Add seed domains to queue')
    parser.add_argument('--force-shutdown-after', type=int, default=3, help='Force shutdown after N signals')
    
    args = parser.parse_args()
    
    processor = QueueProcessor(force_shutdown_after=args.force_shutdown_after)
    
    # Add seed domains if provided
    if args.add_seeds:
        processor.add_seed_domains(args.add_seeds)
    
    # Run the processor
    processor.run(
        max_items=args.max_items,
        max_depth=args.max_depth,
        continuous=args.continuous
    )


if __name__ == "__main__":
    main() 