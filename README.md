# InjectShellcode

The purpose of this code is to inject shellcode into a target process without affecting its threads or creating new ones. It leverages the Sleep function, which is part of a shared library, thus having the shared flag always active. This means that when written to from an external source, the page count (copy on write) isn't triggered. As a result, shellcode can be injected without directly manipulating or creating threads.

## How it works

1. **Get Process ID**: The code continuously checks for the process ID of the target executable named "test.exe" using a helper function `GetPid`.

2. **Open Target Process**: Once the process ID is obtained, it opens the target process with `OpenProcess`, granting all access rights.

3. **Allocate Memory**: Memory is allocated within the target process using `VirtualAllocEx` to hold the shellcode.

4. **Write Shellcode**: The shellcode function `Dtr` is written into the allocated memory using `WriteProcessMemory`.

5. **Relative Jump**: A relative jump is performed from a chosen function (`Sleep` in this case) to the allocated memory containing the shellcode. This jump is facilitated by modifying the target function's instructions temporarily.

6. **Cleanup and Completion**: Finally, the injected shellcode is executed within the target process. Upon completion, handles are closed, and the program terminates.

## Advantages

- **Stealthy Injection**: By leveraging a commonly used function (`Sleep`), the injection remains stealthy and less prone to detection.
- **Thread Safety**: Since the injection doesn't create or interfere with threads directly, it minimizes the chances of crashing or alerting the target process.
- **Reliable Trigger**: The trigger for the injection (Sleep function) is widely used in processes, ensuring a high likelihood of successful injection across various scenarios.

## Bad

- **Dependency on Specific Function**: This method relies on the presence and usability of a specific function (`Sleep` in this case) within the target process. If the function is not present or its behavior changes, the injection may fail.
- **Limited Payload Size**: The size of the shellcode is restricted by the space available within the target function's instructions. Larger payloads may not fit, limiting the complexity of potential exploits.
- **Potential Detection**: While the injection method aims to be stealthy, sophisticated monitoring tools or security software may still detect unusual behavior, such as modification of function instructions or unexpected memory writes.
- **Platform Specificity**: This approach may not be universally applicable across all operating systems or architectures. It is tailored to Windows environments and may require modifications for use on other platforms.
- **Risk of Unintended Consequences**: Manipulating memory and function instructions within a running process carries the risk of unintended side effects, such as crashes or instability, especially if the injected shellcode interacts with the target process in unexpected ways.
