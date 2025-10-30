#!/usr/bin/env python3
"""
CAD Calibration Example: Calibrate Channel Activity Detection thresholds.

This example helps calibrate CAD (Channel Activity Detection) thresholds
for optimal performance. It performs multiple CAD operations with different
threshold values and provides recommendations.

Note: This example only works with SX1262 radios, not KISS TNC devices.
"""

import asyncio
import statistics
import time
from typing import List, Dict, Any

from common import create_radio

# CAD calibration results storage
cad_results: List[Dict[str, Any]] = []


async def perform_cad_sweep(radio, det_peak_range: range, det_min_range: range, samples_per_config: int = 5) -> List[Dict[str, Any]]:
    """Perform a CAD sweep across threshold ranges."""
    results = []
    total_configs = len(det_peak_range) * len(det_min_range)
    current_config = 0
    
    print(f"Starting CAD sweep: {len(det_peak_range)} peak × {len(det_min_range)} min = {total_configs} configurations")
    print(f"Taking {samples_per_config} samples per configuration...")
    print("-" * 60)
    
    for det_peak in det_peak_range:
        for det_min in det_min_range:
            current_config += 1
            print(f"[{current_config:2d}/{total_configs}] Testing det_peak={det_peak:2d}, det_min={det_min:2d}", end=" ")
            
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
                    print(f"\n    Error in sample {sample + 1}: {e}")
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
            print(f"→ {detected_count}/{samples_per_config} detected ({detection_rate:4.1f}%)")
    
    return results


def analyze_cad_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze CAD calibration results and provide recommendations."""
    if not results:
        return {"error": "No results to analyze"}
    
    # Group results by detection rate
    no_detection = [r for r in results if r['detection_rate'] == 0]
    low_detection = [r for r in results if 0 < r['detection_rate'] <= 25]
    medium_detection = [r for r in results if 25 < r['detection_rate'] <= 75]
    high_detection = [r for r in results if r['detection_rate'] > 75]
    
    # Find optimal thresholds (low false positive rate but still sensitive)
    optimal_configs = [r for r in results if 0 < r['detection_rate'] <= 10]  # 0-10% detection rate
    if not optimal_configs:
        optimal_configs = no_detection  # Fall back to no detection if no low-detection configs
    
    # Sort by sensitivity (lower thresholds = more sensitive)
    optimal_configs.sort(key=lambda x: (x['det_peak'], x['det_min']))
    
    analysis = {
        'total_configurations': len(results),
        'no_detection_count': len(no_detection),
        'low_detection_count': len(low_detection),
        'medium_detection_count': len(medium_detection),
        'high_detection_count': len(high_detection),
        'detection_rates': [r['detection_rate'] for r in results],
        'recommended_config': optimal_configs[0] if optimal_configs else None,
        'most_sensitive': min(results, key=lambda x: (x['det_peak'], x['det_min'])),
        'least_sensitive': max(results, key=lambda x: (x['det_peak'], x['det_min'])),
    }
    
    return analysis


def print_calibration_summary(analysis: Dict[str, Any], radio_config: Dict[str, Any]):
    """Print a comprehensive calibration summary."""
    print("\n" + "=" * 60)
    print("CAD CALIBRATION SUMMARY")
    print("=" * 60)
    
    # Radio configuration
    print(f"Radio Configuration:")
    print(f"  Frequency: {radio_config.get('frequency', 0)/1000000:.3f} MHz")
    print(f"  Bandwidth: {radio_config.get('bandwidth', 0)/1000:.1f} kHz")
    print(f"  Spreading Factor: {radio_config.get('spreading_factor', 0)}")
    print(f"  TX Power: {radio_config.get('tx_power', 0)} dBm")
    
    # Results overview
    print(f"\nCalibration Results:")
    print(f"  Total configurations tested: {analysis['total_configurations']}")
    print(f"  No detection (0%): {analysis['no_detection_count']} configs")
    print(f"  Low detection (1-25%): {analysis['low_detection_count']} configs")
    print(f"  Medium detection (26-75%): {analysis['medium_detection_count']} configs")
    print(f"  High detection (>75%): {analysis['high_detection_count']} configs")
    
    if analysis['detection_rates']:
        avg_detection = statistics.mean(analysis['detection_rates'])
        print(f"  Average detection rate: {avg_detection:.1f}%")
    
    # Recommendations
    print(f"\nRecommendations:")
    if analysis['recommended_config']:
        rec = analysis['recommended_config']
        print(f"  RECOMMENDED: det_peak={rec['det_peak']}, det_min={rec['det_min']}")
        print(f"    Detection rate: {rec['detection_rate']:.1f}% (good balance)")
    else:
        print("  No optimal configuration found in tested range")
    
    # Sensitivity range
    most_sens = analysis['most_sensitive']
    least_sens = analysis['least_sensitive']
    print(f"  Most sensitive: det_peak={most_sens['det_peak']}, det_min={most_sens['det_min']} ({most_sens['detection_rate']:.1f}%)")
    print(f"  Least sensitive: det_peak={least_sens['det_peak']}, det_min={least_sens['det_min']} ({least_sens['detection_rate']:.1f}%)")
    
    print("\nNote: Lower detection rates indicate better noise rejection.")
    print("Choose thresholds based on your environment and requirements.")


async def calibrate_cad(radio_type: str = "waveshare"):
    """Main CAD calibration function."""
    # Validate radio type
    if radio_type == "kiss-tnc":
        print("ERROR: CAD calibration is not supported with KISS TNC radios.")
        print("CAD (Channel Activity Detection) is only available on SX1262 hardware.")
        print("Please use --radio-type with 'waveshare', 'uconsole', or 'meshadv-mini'")
        return None
    
    print(f"Starting CAD calibration for {radio_type} radio...")
    print("This will test various CAD threshold combinations to find optimal settings.")
    print()
    
    radio = None
    try:
        # Create radio (this will be an SX1262Radio instance)
        radio = create_radio(radio_type)
        
        # Verify we have an SX1262 radio (CAD is only available on SX1262)
        from pymc_core.hardware.sx1262_wrapper import SX1262Radio
        if not isinstance(radio, SX1262Radio):
            print(f"ERROR: Expected SX1262Radio, got {type(radio).__name__}")
            print("CAD calibration requires SX1262 hardware.")
            return None
        
        # Initialize radio
        print("Initializing radio...")
        radio.begin()
        print("Radio initialized successfully!")
        
        # Get radio configuration for reporting
        radio_config = radio.get_status()
        print(f"Radio config: {radio_config['frequency']/1000000:.3f}MHz, SF{radio_config['spreading_factor']}, {radio_config['bandwidth']/1000:.1f}kHz")
        
        # Wait for radio to settle
        print("Waiting for radio to settle...")
        await asyncio.sleep(2.0)
        
        # Define calibration ranges
        # These ranges cover typical CAD threshold values
        det_peak_range = range(20, 31, 2)    # 20, 22, 24, 26, 28, 30
        det_min_range = range(8, 13, 1)      # 8, 9, 10, 11, 12
        samples_per_config = 3  # Number of samples per threshold combination
        
        print(f"Threshold ranges:")
        print(f"  det_peak: {list(det_peak_range)}")
        print(f"  det_min: {list(det_min_range)}")
        print(f"  samples per config: {samples_per_config}")
        print()
        
        # Perform calibration sweep
        results = await perform_cad_sweep(radio, det_peak_range, det_min_range, samples_per_config)
        
        # Analyze results
        analysis = analyze_cad_results(results)
        
        # Print summary
        print_calibration_summary(analysis, radio_config)
        
        # Store results globally for potential further analysis
        global cad_results
        cad_results = results
        
        return results, analysis
        
    except Exception as e:
        print(f"Calibration failed: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        # Clean up radio
        try:
            if radio is not None and hasattr(radio, 'cleanup'):
                radio.cleanup()  # type: ignore
        except:
            pass


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
    
    args = parser.parse_args()
    
    print("CAD Calibration Tool")
    print("===================")
    print(f"Using {args.radio_type} radio configuration")
    print()
    
    try:
        result = asyncio.run(calibrate_cad(args.radio_type))
        if result:
            print("\nCalibration completed successfully!")
            print("Use the recommended thresholds in your CAD operations.")
        else:
            print("\nCalibration failed!")
    except KeyboardInterrupt:
        print("\nCalibration interrupted by user")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()