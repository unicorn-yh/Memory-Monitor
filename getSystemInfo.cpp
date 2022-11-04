#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <string>
using namespace std;
#pragma comment(lib, "user32.lib")

int main(){
      SYSTEM_INFO siSysInfo;
      GetSystemInfo(&siSysInfo);  // Copy the hardware information to the SYSTEM_INFO structure. 
 
      // Display the contents of the SYSTEM_INFO structure. 
      printf("\n========== Hardware information ==========\n");  

      //printf("Minimum Application Address: %u\n",siSysInfo.lpMinimumApplicationAddress);
      //printf("Maximum Application Address: %u\n",siSysInfo.lpMaximumApplicationAddress);

      //printf("OEM ID: %u\n", siSysInfo.dwOemId);

      printf("Number of processors: %u\n", siSysInfo.dwNumberOfProcessors);  //The number of logical processors in the current group. To retrieve the current processor group, use the GetLogicalProcessorInformation function.
      
      printf("Page size: %u\n", siSysInfo.dwPageSize);   //The page size and the granularity of page protection and commitment. This is the page size used by the VirtualAlloc function.
      
      //Processor Type
      unsigned processor_type = siSysInfo.dwProcessorType;  //An obsolete member that is retained for compatibility.
      char* type;
      if(processor_type == 386){
            type = "PROCESSOR_INTEL_386";
      }
      else if(processor_type == 486){
            type = "PROCESSOR_INTEL_486";
      }
      else if(processor_type == 586){
            type = "PROCESSOR_INTEL_PENTIUM";
      }
      else if(processor_type == 2200){
            type = "PROCESSOR_INTEL_IA64";
      }
      else if(processor_type == 8664){
            type = "PROCESSOR_AMD_X8664";
      }
      else{
            type = "PROCESSOR_ARM";
      }
      printf("Processor type: %s\n", type); 
      
      
      printf("Minimum application address: %lx\n", siSysInfo.lpMinimumApplicationAddress);  //A pointer to the lowest memory address accessible to applications and dynamic-link libraries (DLLs).
      
      printf("Maximum application address: %lx\n", siSysInfo.lpMaximumApplicationAddress);  //A pointer to the highest memory address accessible to applications and DLLs.
      
      printf("Active processor mask: %u\n", siSysInfo.dwActiveProcessorMask);  //A mask representing the set of processors configured into the system. Bit 0 is processor 0; bit 31 is processor 31.
      
      //Processor Architecture
      unsigned architecture = siSysInfo.wProcessorArchitecture; 
      char* arch;
      if(architecture == 9){
            arch = "x64 (AMD or Intel)";
      }
      else if(architecture == 5){
            arch = "ARM";
      }
      else if(architecture == 12){
            arch = "ARM64";
      }
      else if(architecture == 6){
            arch = "Intel Itanium-based";
      }
      else if(architecture == 0){
            arch = "x86";
      }
      else{
            arch = "Unknown architecture";
      }
      printf("Processor architecture: %s\n",arch);   //9=x64 Intel
      
      printf("Processor level: %u\n",siSysInfo.wProcessorLevel); //The architecture-dependent processor level. It should be used only for display purposes. To determine the feature set of a processor, use the IsProcessorFeaturePresent function.

      printf("Processor Revision: %u\n",siSysInfo.wProcessorRevision); 
      
      printf("Allocation Granularity: %u\n",siSysInfo.dwAllocationGranularity); //The granularity for the starting address at which virtual memory can be allocated. For more information, see VirtualAlloc.
      
      printf("==========================================\n");  

      return 0;
}