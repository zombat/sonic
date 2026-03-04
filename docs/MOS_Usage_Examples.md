# S.O.N.I.C. Advanced RTP MOS Analysis - Usage Examples

## 🚀 Overview

S.O.N.I.C. now includes **Advanced RTP MOS (Mean Opinion Score) Analysis** with flexible command-line options for comprehensive VoIP quality assessment.

## 📋 Command-Line Options

### **New Quality Analysis Flags**

```bash
--mos           # Enable Advanced RTP MOS analysis (ITU-T G.107 E-Model)
--quality       # Enable Call Quality Scoring analysis
--quality-only  # Run ONLY quality analysis (no AI models)
```

## 🎯 Usage Examples

### **1. Quality-Only Analysis Mode**
*Perfect for quick quality assessment without AI overhead*

```bash
# Run comprehensive quality analysis (MOS + Quality Scoring)
python3 sonic.py --file capture.pcapng --quality-only

# Output includes:
# ✅ Call Quality Scoring (0-100 with A+ to F grades)
# ✅ Advanced RTP MOS Analysis (1.0-5.0 with ITU-T compliance)
# ✅ Fast execution (no AI model loading)
# ✅ Detailed quality reports saved to markdown
```

### **2. MOS Analysis with AI Models**
*Combine MOS analysis with AI diagnostic insights*

```bash
# Add MOS analysis to fast AI analysis
python3 sonic.py --file capture.pcapng --mos --model fast

# Add MOS analysis to detailed AI analysis  
python3 sonic.py --file capture.pcapng --mos --model detailed

# Add MOS analysis to combined AI analysis (recommended)
python3 sonic.py --file capture.pcapng --mos --model combined
```

### **3. Complete Quality Analysis with AI**
*Full quality assessment plus AI diagnostic insights*

```bash
# Enable both quality scoring and MOS analysis with AI
python3 sonic.py --file capture.pcapng --quality --mos --model combined

# This provides:
# ✅ AI-powered SIP diagnostic analysis
# ✅ Traditional call quality scoring (0-100)
# ✅ Advanced RTP MOS analysis (1.0-5.0)
# ✅ Combined quality metrics in reports
```

### **4. Quality Analysis Only - Individual Components**
*Test specific quality components independently*

```bash
# Run only Call Quality Scoring (no MOS)
python3 sonic.py --file capture.pcapng --quality --quality-only

# Run only MOS Analysis (no traditional scoring)
python3 sonic.py --file capture.pcapng --mos --quality-only
```

## 📊 Sample Outputs

### **Successful Call Example (MG-SIP-1.pcapng)**

```bash
python3 sonic.py --file samples/MG-SIP-1.pcapng --quality-only
```

**Output Highlights:**
```
🎯 OVERALL QUALITY SCORE: 73.1/100
🏆 QUALITY GRADE: B - Good quality

📊 OVERALL MOS SCORE: 4.38/5.0  
🏆 QUALITY CATEGORY: Good
📈 MOS RANGE: 4.38 - 4.38
   ✨ High-quality voice - business grade

🔍 INDIVIDUAL STREAM ANALYSIS:
   Stream 1 (SSRC: 0x6fbf6b3b): MOS 4.38 (Good)
   Stream 2 (SSRC: 0x000023bc): MOS 4.38 (Good)
```

### **Failure Scenario Example (NEC_failure_sample.pcapng)**

```bash
python3 sonic.py --file samples/NEC_failure_sample.pcapng --mos --model fast
```

**Output Highlights:**
```
🎯 OVERALL QUALITY SCORE: 42.5/100
🏆 QUALITY GRADE: D - Poor quality

⚠️ NO RTP STREAMS DETECTED
   Unable to calculate MOS scores without RTP data

💡 MOS IMPROVEMENT RECOMMENDATIONS:
   📦 Verify RTP traffic is present in capture
   🔍 Check if media streams use non-standard ports
```

## 🏆 Quality Assessment Features

### **Call Quality Scoring (--quality)**
- **0-100 Point Scale** with A+ to F letter grades
- **Weighted Component Analysis**: Network (40%), Protocol (30%), Codec (20%), Completion (10%)
- **Detailed Breakdowns** for troubleshooting
- **Professional Recommendations** for improvements

### **Advanced RTP MOS Analysis (--mos)**
- **ITU-T G.107 E-Model** compliance for industry standards
- **1.0-5.0 MOS Scale** (1=Bad, 5=Excellent)
- **Multi-Stream Analysis** with individual stream assessment
- **Component Scoring**: Packet Loss, Jitter, Latency, Codec Quality
- **Intelligent Recommendations** based on ITU-T guidelines

## 🔧 Performance Comparison

| Mode | Analysis Time | AI Models | Quality Scoring | MOS Analysis |
|------|--------------|-----------|-----------------|--------------|
| `--quality-only` | ~2-5 seconds | ❌ | ✅ | ✅ |
| `--model fast` | ~1-5 seconds | ✅ Fast | ❌ | ❌ |
| `--model fast --mos` | ~3-8 seconds | ✅ Fast | ❌ | ✅ |
| `--model combined --quality --mos` | ~30-60 seconds | ✅ Both | ✅ | ✅ |

## 💡 Best Practices

### **For Quick Quality Assessment:**
```bash
# Fast quality check without AI overhead
python3 sonic.py --file capture.pcapng --quality-only
```

### **For Production Monitoring:**
```bash
# Comprehensive analysis with all features
python3 sonic.py --file capture.pcapng --quality --mos --model combined
```

### **For Troubleshooting:**
```bash
# Focus on MOS analysis for voice quality issues
python3 sonic.py --file capture.pcapng --mos --model fast
```

### **For Quality Reports:**
```bash
# Generate detailed quality reports
python3 sonic.py --file capture.pcapng --quality-only --save_file quality_report.md
```

## 📚 Technical Details

### **ITU-T Standards Compliance**
- **G.107 E-Model**: Primary MOS calculation methodology
- **G.1020**: Packet loss impairment modeling
- **G.114**: Delay budget and jitter analysis
- **Codec Standards**: G.711, G.722, G.729, Opus quality baselines

### **Quality Metrics**
- **Packet Loss Impact**: 0-100% with codec-specific sensitivity
- **Jitter Analysis**: ITU-T G.114 delay budget considerations
- **Latency Assessment**: One-way delay calculations
- **Codec Quality**: Baseline quality ratings for standard codecs

### **Reporting Features**
- **Visual Quality Indicators**: Emoji-based status indicators
- **Component Breakdowns**: Detailed scoring for each quality factor
- **Professional Recommendations**: Actionable improvement guidance
- **Markdown Reports**: Professional documentation with quality metrics

## 🎯 Use Cases

### **VoIP Engineers**
- **Quality Baseline Establishment**: Document current voice quality levels
- **Troubleshooting**: Identify specific quality degradation factors
- **Optimization**: Target improvements based on component scoring

### **System Administrators**
- **Monitoring**: Quick quality checks without complex analysis
- **Performance Validation**: Verify voice quality meets standards
- **Documentation**: Generate quality reports for stakeholders

### **Quality Assurance**
- **Standardized Assessment**: ITU-T compliant quality measurements
- **Objective Scoring**: Replace subjective quality assessment
- **Compliance Documentation**: Professional quality reporting

## 🚀 Advanced Examples

### **Batch Quality Analysis**
```bash
# Analyze multiple captures with quality assessment
for file in samples/*.pcapng; do
    echo "Analyzing $file..."
    python3 sonic.py --file "$file" --quality-only --save_file "${file%.pcapng}_quality.md"
done
```

### **Quality Comparison**
```bash
# Compare quality before and after network changes
python3 sonic.py --file before_optimization.pcapng --quality-only --save_file before_quality.md
python3 sonic.py --file after_optimization.pcapng --quality-only --save_file after_quality.md
```

### **Comprehensive Diagnostic**
```bash
# Full analysis with all features for critical issues
python3 sonic.py --file problem_capture.pcapng \
                 --quality --mos \
                 --model combined \
                 --verbose \
                 --save_file comprehensive_analysis.md
```

---

## ✅ Summary

The Advanced RTP MOS Analysis integration provides:

- **🎯 Flexible Quality Assessment**: Choose quality-only mode or combine with AI analysis
- **📊 Industry Standards**: ITU-T G.107 E-Model compliance for professional use
- **⚡ Performance Options**: Fast quality checks or comprehensive analysis
- **📋 Professional Reporting**: Detailed quality metrics with actionable recommendations
- **🔧 Easy Integration**: Simple command-line flags for immediate use

*Perfect for VoIP engineers, system administrators, and quality assurance teams requiring professional-grade voice quality assessment.*
