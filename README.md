QuickTrack Control App
------------------------------------------------------------------------

Copyright (c) 2020 Wi-Fi Alliance                                             
Permission to a personal, non-exclusive, non-transferable use of this         
software in object code form only, solely for the purposes of supporting      
Wi-Fi certification program development, Wi-Fi pre-certification testing,     
and formal Wi-Fi certification testing by authorized test labs, Wi-Fi         
Alliance members in good standing and their customers, provided that any      
part of this software shall not be copied or reproduced in any way. Wi-Fi     
Alliance Software License Agreement governing this software can be found at
https://www.wi-fi.org/file/wi-fi-alliance-software-end-user-license-agreement.<br />
The foregoing license shall terminate if Customer breaches any term hereof    
and fails to cure such breach within five (5) days of notice of breach.       

THE SOFTWARE IS PROVIDED 'AS IS' AND THE AUTHOR DISCLAIMS ALL                 
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                 
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL                  
THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR                    
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING                     
FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF                    
CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT                    
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS                       
SOFTWARE.

------------------------------------------------------------------------
Build & Run
------------------------------------------------------------------------
make clean ; make <br />
sudo ./app -p &lt;port&gt;

------------------------------------------------------------------------
OpenWRT Prerequisite
------------------------------------------------------------------------
1. Add firewall rule to allow to run ControlAppC on WAN<br />
uci add firewall rule <br />
uci add_list firewall.@rule[10].target='ACCEPT'<br />
uci add_list firewall.@rule[10].src='wan'<br />
uci add_list firewall.@rule[10].proto='tcp udp'<br />
uci add_list firewall.@rule[10].dest_port='9004'<br />
uci add_list firewall.@rule[10].name='ControlAppC'<br />
uci commit<br />
2. Disable Wi-Fi for the clean start<br />
uci delete wireless.@wifi-iface[0]<br />
uci delete wireless.@wifi-iface[1]<br />
uci commit<br />

------------------------------------------------------------------------
OpenWRT Build
------------------------------------------------------------------------
Change Makefile <br />
ROLE = openwrt <br />
make clean ; make <br />

Use scp to copy app to OpenWRT <br />
./app -p &lt;port&gt;
