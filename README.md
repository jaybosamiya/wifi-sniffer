WiFi Sniffer
============

With the ever increasing dependance on wireless solutions, it sometimes is useful to know the devices around you. This software aims to help know the MAC addresses of the devices that are leaving any sort of trace on the airwaves.

This software is meant for educational purpose only. The author will not be held liable for any harm that is related to the software.

Note: This software was created as an assignment/project as part of the Operating Systems course at IIT Roorkee.

Instructions for Compilation
----------------------------

Compiling the sniffer follows the steps of standard CMake based build.

Basically, just run the following steps in the source directory:

```
mkdir bin
cd bin
cmake ..
make
```

This will create a `wifi-sniffer` file which can then be used to sniff packets from an wireless interface.

Usage Syntax
------------

Running `./wifi-sniffer` without any parameters shows the usage

```
Usage: ./wifi-sniffer [options] interface
  -m, --macstat   : Show number of detections of each MAC and timestamps
  -t, --time t    : Run sniffer for t seconds (default: 60)
  -v, --verbose   : Output more information
  -d, --debug     : Show debugging information
  -h, --help      : Show this help text

Note: This program needs to be run as root
```

Do note that you need to have a wireless interface which supports "Monitor" mode to be able to use this software.

Legal
-----

Please read the [LICENSE](LICENSE) file to know legal details of how you are allowed to use this software. But in short, this software is licensed under MIT License.

Disclaimer
----------

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.