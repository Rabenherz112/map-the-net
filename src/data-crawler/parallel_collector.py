import multiprocessing
import time
import logging
import json
from concurrent.futures import ProcessPoolExecutor, as_completed
from domain_collector import DomainCollector
from config import COLLECTION_CONFIG, AUTO_UPDATE_CONFIG
from version import __version__
from auto_update import AutoUpdate, default_restart_callback
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ParallelDomainCollector:
    def __init__(self, worker_id=None):
        self.worker_id = worker_id or os.getpid()
        self.collector = DomainCollector()
    
    def collect_single_domain(self, domain_name):
        """Collect data for a single domain"""
        try:
            logger.info(f"Worker {self.worker_id}: Collecting {domain_name}")
            domain_id, relationships = self.collector.collect_domain_data(domain_name)
            return {
                'domain': domain_name,
                'domain_id': domain_id,
                'relationships_count': len(relationships),
                'status': 'success'
            }
        except Exception as e:
            logger.error(f"Worker {self.worker_id}: Error collecting {domain_name}: {e}")
            return {
                'domain': domain_name,
                'error': str(e),
                'status': 'failed'
            }
    
    def collect_domains_batch(self, domains):
        """Collect data for a batch of domains"""
        results = []
        for domain in domains:
            result = self.collect_single_domain(domain)
            results.append(result)
            time.sleep(COLLECTION_CONFIG['request_delay'])
        return results
    
    def close(self):
        """Clean up resources"""
        self.collector.close()


def worker_process(worker_id, domains, result_queue):
    """Worker process function"""
    collector = ParallelDomainCollector(worker_id)
    try:
        results = collector.collect_domains_batch(domains)
        result_queue.put((worker_id, results))
    except Exception as e:
        logger.error(f"Worker {worker_id} failed: {e}")
        result_queue.put((worker_id, []))
    finally:
        collector.close()


def distribute_domains(domains, num_workers):
    """Distribute domains across workers"""
    chunk_size = max(1, len(domains) // num_workers)
    chunks = []
    
    for i in range(0, len(domains), chunk_size):
        chunk = domains[i:i + chunk_size]
        chunks.append(chunk)
    
    return chunks


def run_parallel_collection(domains, num_workers=None):
    """Run domain collection in parallel"""
    if num_workers is None:
        num_workers = min(COLLECTION_CONFIG['parallel_workers'], len(domains))
    
    logger.info(f"Starting parallel collection with {num_workers} workers for {len(domains)} domains")
    
    # Distribute domains across workers
    domain_chunks = distribute_domains(domains, num_workers)
    
    # Create result queue
    result_queue = multiprocessing.Queue()
    
    # Start worker processes
    processes = []
    for i, chunk in enumerate(domain_chunks):
        if chunk:  # Only create process if there are domains to process
            p = multiprocessing.Process(
                target=worker_process,
                args=(i, chunk, result_queue)
            )
            p.start()
            processes.append(p)
    
    # Collect results
    all_results = []
    for _ in range(len(processes)):
        worker_id, results = result_queue.get()
        all_results.extend(results)
        logger.info(f"Worker {worker_id} completed with {len(results)} results")
    
    # Wait for all processes to finish
    for p in processes:
        p.join()
    
    return all_results


def load_domains_from_file(filename):
    """Load domains from a text file (one domain per line)"""
    domains = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith('#'):
                    domains.append(domain)
        logger.info(f"Loaded {len(domains)} domains from {filename}")
    except FileNotFoundError:
        logger.error(f"Domain file {filename} not found")
    return domains


def save_results_to_file(results, filename):
    """Save collection results to JSON file"""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"Results saved to {filename}")
    except Exception as e:
        logger.error(f"Error saving results: {e}")


def main():
    """Main function for parallel collection"""
    # Start auto-update checker
    auto_updater = AutoUpdate(AUTO_UPDATE_CONFIG, __version__, default_restart_callback)
    auto_updater.start_periodic_check()

    # Example domains - you can load from file or define here
    domains = [
        'example.com',
        'google.com',
        'github.com',
        'stackoverflow.com',
        'reddit.com',
        'wikipedia.org',
        'amazon.com',
        'microsoft.com',
        'apple.com',
        'netflix.com'
    ]
    
    # Or load from file
    # domains = load_domains_from_file('domains.txt')
    
    if not domains:
        logger.error("No domains to process")
        return
    
    # Run parallel collection
    results = run_parallel_collection(domains)
    
    # Save results
    save_results_to_file(results, 'collection_results.json')
    
    # Print summary
    successful = sum(1 for r in results if r['status'] == 'success')
    failed = sum(1 for r in results if r['status'] == 'failed')
    
    logger.info(f"Collection completed: {successful} successful, {failed} failed")


if __name__ == "__main__":
    main()