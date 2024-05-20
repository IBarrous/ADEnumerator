# ADEnumerator
<h3>Description :</h3>
a custom powershell script designed to automate the enumeration of AD infrastructure by using PowerView.
<h3>Usage :</h3>
<pre><code>.\ADEnumerator.ps1 [-SamAccountName] [-h]</code></pre>
<h3>Options :</h3>
<ul>
<li>-SamAccountName [String] :
            Specify the SAM account name of a user or computer to retrieve additional details such as the groups it 
            belongs to, whether it is allowed to delegate, if it is kerberoastable or ASREP roastable, the associated ACLs
            and the derived ACLs from the groups it belongs to.
</li>
<li>
-h : Shows A Detailed Help Message.
</li>
</ul>
<h3>Details :</h3>
        This script enumerates various Active Directory details including the current domain, domain controllers,
        OUs (Organizational Units), GPOs (Group Policy Objects) and their associated OUs, computers, users,
        unconstrained/constrained/RBCD (Resource-Based Constrained Delegation) computers and users,
        ASREP roasting users, kerberoastable users, and interesting ACLs.
<br />
<br />
<p align="center"><i>Example of a thorough scan of the whole AD infrastructure</i></p>

<div align="center">
  <img src="https://github.com/IBarrous/ADEnumerator/assets/126162952/5d822086-cfb2-4dc9-975c-a29f6b9bdfd6" alt="image1">
</div>

<p align="center"><i>Example of a specific scan of a SamAccountName</i></p>
<div align="center">
  <img src="https://github.com/IBarrous/ADEnumerator/assets/126162952/bd14e32d-8744-47d2-a11a-d38ccecd9873" alt="image2">
</div>
<h3>Resources:</h3>
<ul>
	<li><a href="https://github.com/ZeroDayLab/PowerSploit/blob/master/Recon/PowerView.ps1"><b>PowerView</b></a></li>
</ul>
