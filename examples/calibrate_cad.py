#!/usr/bin/env python3
"""
CAD Calibration Example: Calibrate Channel Activity Detection thresholds.

This example helps calibrate CAD (Channel Activity Detection) thresholds
for optimal performance. It performs multiple CAD operations with different
threshold values and provides recommendations.

Note: This example only works with SX1262 radios, not KISS TNC devices.
"""

import asyncio
import csv
import logging
import statistics
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from common import create_radio

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# CAD calibration results storage
cad_results: List[Dict[str, Any]] = []


class CadCalibrationAnalyzer:
    """Analyzes CAD calibration results and provides recommendations."""
    
    def __init__(self, results: List[Dict[str, Any]]):
        """Initialize analyzer with calibration results."""
        self.results = results
        self.analysis = self._analyze_results()
    
    def _analyze_results(self) -> Dict[str, Any]:
        """Analyze CAD calibration results and provide recommendations."""
        if not self.results:
            return {"error": "No results to analyze"}
        
        # Group results by detection rate
        no_detection = [r for r in self.results if r['detection_rate'] == 0]
        low_detection = [r for r in self.results if 0 < r['detection_rate'] <= 25]
        medium_detection = [r for r in self.results if 25 < r['detection_rate'] <= 75]
        high_detection = [r for r in self.results if r['detection_rate'] > 75]
        
        # Find optimal thresholds (low false positive rate but still sensitive)
        optimal_configs = [r for r in self.results if 0 < r['detection_rate'] <= 10]  # 0-10% detection rate
        if not optimal_configs:
            optimal_configs = no_detection  # Fall back to no detection if no low-detection configs
        
        # Sort by sensitivity (lower thresholds = more sensitive)
        optimal_configs.sort(key=lambda x: (x['det_peak'], x['det_min']))
        
        analysis = {
            'total_configurations': len(self.results),
            'no_detection_count': len(no_detection),
            'low_detection_count': len(low_detection),
            'medium_detection_count': len(medium_detection),
            'high_detection_count': len(high_detection),
            'detection_rates': [r['detection_rate'] for r in self.results],
            'recommended_config': optimal_configs[0] if optimal_configs else None,
            'most_sensitive': min(self.results, key=lambda x: (x['det_peak'], x['det_min'])),
            'least_sensitive': max(self.results, key=lambda x: (x['det_peak'], x['det_min'])),
        }
        
        return analysis
    
    def print_summary(self, radio_config: Dict[str, Any]) -> None:
        """Print a comprehensive calibration summary."""
        logger.info("=" * 60)
        logger.info("CAD CALIBRATION SUMMARY")
        logger.info("=" * 60)
        
        # Radio configuration
        logger.info("Radio Configuration:")
        logger.info(f"  Frequency: {radio_config.get('frequency', 0)/1000000:.3f} MHz")
        logger.info(f"  Bandwidth: {radio_config.get('bandwidth', 0)/1000:.1f} kHz")
        logger.info(f"  Spreading Factor: {radio_config.get('spreading_factor', 0)}")
        logger.info(f"  TX Power: {radio_config.get('tx_power', 0)} dBm")
        
        # Results overview
        logger.info("Calibration Results:")
        logger.info(f"  Total configurations tested: {self.analysis['total_configurations']}")
        logger.info(f"  No detection (0%%): {self.analysis['no_detection_count']} configs")
        logger.info(f"  Low detection (1-25%%): {self.analysis['low_detection_count']} configs")
        logger.info(f"  Medium detection (26-75%%): {self.analysis['medium_detection_count']} configs")
        logger.info(f"  High detection (>75%%): {self.analysis['high_detection_count']} configs")
        
        if self.analysis['detection_rates']:
            avg_detection = statistics.mean(self.analysis['detection_rates'])
            logger.info(f"  Average detection rate: {avg_detection:.1f}%%")
        
        # Recommendations
        logger.info("Recommendations:")
        if self.analysis['recommended_config']:
            rec = self.analysis['recommended_config']
            logger.info(f"  RECOMMENDED: det_peak={rec['det_peak']}, det_min={rec['det_min']}")
            logger.info(f"    Detection rate: {rec['detection_rate']:.1f}%% (good balance)")
        else:
            logger.warning("  No optimal configuration found in tested range")
        
        # Sensitivity range
        most_sens = self.analysis['most_sensitive']
        least_sens = self.analysis['least_sensitive']
        logger.info(f"  Most sensitive: det_peak={most_sens['det_peak']}, det_min={most_sens['det_min']} ({most_sens['detection_rate']:.1f}%%)")
        logger.info(f"  Least sensitive: det_peak={least_sens['det_peak']}, det_min={least_sens['det_min']} ({least_sens['detection_rate']:.1f}%%)")
        
        logger.info("Note: Lower detection rates indicate better noise rejection.")
        logger.info("Choose thresholds based on your environment and requirements.")
    
    def export_csv(self, filename: str) -> None:
        """Export calibration results to CSV file."""
        try:
            with open(filename, 'w', newline='') as csvfile:
                fieldnames = [
                    'det_peak', 'det_min', 'samples', 'detections', 
                    'detection_rate', 'timestamp'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in self.results:
                    row = {k: result.get(k, '') for k in fieldnames}
                    writer.writerow(row)
            
            logger.info(f"Results exported to {filename}")
        except Exception as e:
            logger.error(f"Failed to export CSV: {e}")


def get_sf_based_thresholds(spreading_factor: int) -> Tuple[range, range]:
    """Get CAD threshold ranges based on spreading factor."""
    # SF-based threshold ranges (based on Semtech recommendations)
    sf_thresholds = {
        7: (range(18, 27, 2), range(8, 13, 1)),   # det_peak: 18-26, det_min: 8-12
        8: (range(18, 27, 2), range(8, 13, 1)),   # det_peak: 18-26, det_min: 8-12
        9: (range(20, 29, 2), range(9, 14, 1)),   # det_peak: 20-28, det_min: 9-13
        10: (range(22, 31, 2), range(9, 14, 1)),  # det_peak: 22-30, det_min: 9-13
        11: (range(24, 33, 2), range(10, 15, 1)), # det_peak: 24-32, det_min: 10-14
        12: (range(26, 35, 2), range(10, 15, 1)), # det_peak: 26-34, det_min: 10-14
    }
    
    # Default to SF7 ranges if unknown SF
    return sf_thresholds.get(spreading_factor, sf_thresholds[7])





async def perform_cad_sweep(
    radio, 
    det_peak_range: range, 
    det_min_range: range, 
    samples_per_config: int = 3
) -> List[Dict[str, Any]]:
    """Perform a CAD sweep across threshold ranges."""
    results = []
    total_configs = len(det_peak_range) * len(det_min_range)
    current_config = 0
    
    logger.info(f"Starting CAD sweep: {len(det_peak_range)} peak × {len(det_min_range)} min = {total_configs} configurations")
    logger.info(f"Taking {samples_per_config} samples per configuration...")
    logger.info("-" * 60)
    
    for det_peak in det_peak_range:
        for det_min in det_min_range:
            current_config += 1
            
            # Take multiple samples for this configuration
            sample_results = []
            detected_count = 0
            
            for sample in range(samples_per_config):
                try:
                    # Perform CAD with calibration data
                    result = await radio.perform_cad(
                        det_peak=det_peak,
                        det_min=det_min,
                        timeout=2.0,
                        calibration=True
                    )
                    
                    sample_results.append(result)
                    if result.get('detected', False):
                        detected_count += 1
                        
                    # Small delay between samples
                    await asyncio.sleep(0.1)
                    
                except Exception as e:
                    logger.warning(f"Error in config {current_config}, sample {sample + 1}: {e}")
                    continue
            
            # Calculate statistics for this configuration
            detection_rate = (detected_count / samples_per_config) * 100 if samples_per_config > 0 else 0
            
            config_result = {
                'det_peak': det_peak,
                'det_min': det_min,
                'samples': samples_per_config,
                'detections': detected_count,
                'detection_rate': detection_rate,
                'sample_results': sample_results,
                'timestamp': time.time()
            }
            
            results.append(config_result)
            logger.info(f"[{current_config:2d}/{total_configs}] det_peak={det_peak:2d}, det_min={det_min:2d} → {detected_count}/{samples_per_config} detected ({detection_rate:4.1f}%%)")
    
    return results


async def calibrate_cad(
    radio_type: str = "waveshare", 
    export_csv: Optional[str] = None
) -> Optional[Tuple[List[Dict[str, Any]], Dict[str, Any]]]:
    """Main CAD calibration function."""
    # Validate radio type
    if radio_type == "kiss-tnc":
        logger.error("CAD calibration is not supported with KISS TNC radios.")
        logger.error("CAD (Channel Activity Detection) is only available on SX1262 hardware.")
        logger.error("Please use --radio-type with 'waveshare', 'uconsole', or 'meshadv-mini'")
        return None
    
    logger.info(f"Starting CAD calibration for {radio_type} radio...")
    logger.info("This will test various CAD threshold combinations to find optimal settings.")
    
    radio = None
    try:
        # Create radio (this will be an SX1262Radio instance)
        radio = create_radio(radio_type)
        
        # Verify we have an SX1262 radio (CAD is only available on SX1262)
        from pymc_core.hardware.sx1262_wrapper import SX1262Radio
        if not isinstance(radio, SX1262Radio):
            logger.error(f"Expected SX1262Radio, got {type(radio).__name__}")
            logger.error("CAD calibration requires SX1262 hardware.")
            return None
        
        # Initialize radio
        logger.info("Initializing radio...")
        radio.begin()
        logger.info("Radio initialized successfully!")
        
        # Get radio configuration for reporting
        radio_config = radio.get_status()
        sf = radio_config.get('spreading_factor', 11)
        logger.info(f"Radio config: {radio_config['frequency']/1000000:.3f}MHz, SF{sf}, {radio_config['bandwidth']/1000:.1f}kHz")
        
        # Wait for radio to settle
        logger.info("Waiting for radio to settle...")
        await asyncio.sleep(2.0)
        
        # Get SF-based threshold ranges
        det_peak_range, det_min_range = get_sf_based_thresholds(sf)
        samples_per_config = 3  # Number of samples per threshold combination
        
        logger.info(f"SF{sf}-optimized threshold ranges:")
        logger.info(f"  det_peak: {list(det_peak_range)}")
        logger.info(f"  det_min: {list(det_min_range)}")
        logger.info(f"  samples per config: {samples_per_config}")
        
        # Perform calibration sweep
        results = await perform_cad_sweep(
            radio, 
            det_peak_range, 
            det_min_range, 
            samples_per_config
        )
        
        # Analyze results
        analyzer = CadCalibrationAnalyzer(results)
        
        # Print summary
        analyzer.print_summary(radio_config)
        
        # Export CSV if requested
        if export_csv:
            analyzer.export_csv(export_csv)
        
        # Store results globally for potential further analysis
        global cad_results
        cad_results = results
        
        return results, analyzer.analysis
        
    except Exception as e:
        logger.error(f"Calibration failed: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        # Clean up radio
        if radio is not None:
            try:
                if hasattr(radio, 'cleanup'):
                    radio.cleanup()  # type: ignore
                    logger.info("Radio cleanup completed")
            except Exception as e:
                logger.warning(f"Error during radio cleanup: {e}")


def main():
    """Main function for running the CAD calibration."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Calibrate CAD thresholds for SX1262 radio")
    parser.add_argument(
        "--radio-type",
        choices=["waveshare", "uconsole", "meshadv-mini"],  # Note: kiss-tnc excluded
        default="waveshare",
        help="SX1262 radio hardware type (default: waveshare)"
    )
    parser.add_argument(
        "--export-csv",
        type=str,
        help="Export results to CSV file (e.g., cad_results.csv)"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    
    logger.info("CAD Calibration Tool")
    logger.info("===================")
    logger.info(f"Using {args.radio_type} radio configuration")
    
    # Validate export path
    if args.export_csv:
        export_path = Path(args.export_csv)
        if export_path.exists():
            logger.warning(f"CSV file {args.export_csv} already exists and will be overwritten")
        logger.info(f"Results will be exported to: {args.export_csv}")
    
    logger.info("")
    logger.info("CAD Calibration Notes:")
    logger.info("- 0% detection = quiet RF environment (good for mesh networking)")
    logger.info("- Higher detection rates may indicate RF noise or interference")
    logger.info("- Recommended thresholds balance sensitivity vs false positives")
    logger.info("")
    
    try:
        result = asyncio.run(calibrate_cad(
            radio_type=args.radio_type,
            export_csv=args.export_csv
        ))
        
        if result:
            logger.info("Calibration completed successfully!")
            logger.info("Use the recommended thresholds in your CAD operations.")
        else:
            logger.error("Calibration failed!")
            exit(1)
            
    except KeyboardInterrupt:
        logger.warning("Calibration interrupted by user")
        exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        exit(1)


if __name__ == "__main__":
    main()