What are DDoS attacks?

Denial of service is a cyber attack in which the perpetrator seeks to make a machine or network resource unavailable to its intended users by temporarily or indefinitely disrupting services of a host connected to the internet. 

Combine the data from the 3 datasets i.e. CicDos2019, ISCXIDS2012 and the signature dataset and create a raw dataset that contains data regarding the normal traffic (from CicDos2019 and ISCXIDS2012). The data regarding the DDOS attack is obtained from the signature dataset that is made in the lab under a controlled environment.
1.A feature selection algorithm is applied on the raw data in order to reduce the number of variable and assess their importance in the accurate prediction and detection of DDOS attack.

2.A new customized dataset is thus obtained and further machine learning algorithms are applied to it.

3.Model with the highest accuracy is chosen for detection of DDOS attacks.

How to run?
1.cd ddos

2.Install requirements - python install -r requirements.txt

python DDoSDetector.py

