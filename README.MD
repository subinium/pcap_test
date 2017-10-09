# pcap_test

## Personal Study

네트워크를 처음 배워 과제가 무엇을 요구하는지 이해할 수 없었다.(수업이 너무 빠르다...)

차근차근 이해해 보자.

```
과제

[report]
pcap_test 프로그램을 작성하여라.

[힌트]
송수신되는 packet을 capture하여 다음과 같은 정보를 출력하는 C/C++ 기반 프로그램을 작성하라.

Ethernet Header의 src mac / dst mac
(IP인 경우) IP Header의 src ip / dst ip
(TCP인 경우) TCP Header의 src port / dst port
(Data가 존재하는 경우) 해당 Payload(Data)의 hexa decimal value(16바이트까지만)

TCP packet이 잡히는 경우 "ETH + IP + TCP + DATA" 로 구성이 됨. Ethernet, IP, TCP Header 구조체는 검색을 통하여 struct 정보를 인용하거나 직접 struct를 만들어 사용해도 됨(방법은 각자 알아서).
```

#### pcap

pcap이란 packet capture의 준말로 패킷을 잡는 것이다. 패킷이란 네트워크에서 전달하는 정보들을 묶어놓은 집합이다.

수업 중 Wireshark로 잡는 정보들이 모두 패킷인거다. webhacking에서 Burp Suite이나 Paros에서는 수많은 packet중에서도 http packet을 잡는 툴이다.

그렇다면 C언어로 이 패킷을 잡아 분석하는게 우선적인 과제다.

패킷 파일은 크게 다음과 같은 구조로 이루어져있다고 한다.

```
PCAP header | Packet Header | Packet Data | Packet Header | ...
```

그 패킷들의 종류가 수업에서 설명한 Ethernet, IP, TCP 인것이다.

#### Ethernet, IP, TCP

네트워크 계층은 다행히도 초반 내용이라 이해가 됬다.

**Ethernet** 은 데이터 링크 계층의 패킷으로 각 기기들이 48비트 길이의 MAC주소를 가지고 서로 통신한다.

MAC은 media access control의 약자였다.
그래서 오는 source mac과 가는 destination mac이 각각 24비트 즉 16진수 수(4비트) 6(Byte)개로 표현할 수 있는 것이다.

Ethernet header
```
 Destination MAC Address(6B)
 Source MAC Address(6B)
 Ethernet Type(2B)
```
여기서 Type에 따라서 L3패킷이 정해지는데 0x0800은 ipv4, 0x0806은 arp, 0x8100이면 VLAN Tag 이며 우리는 ipv4의 값일때만 계속 진행하면 되는 것이다.

**IP** 는 흔히 말하는 ip로 3자리수 4개로 이루어진 주소이다. 주로 20Byte로 이루어져 255이하의 수 4개로 표현한다.

IP header
```
 Destination IP Address(4B)
 Source IP Address(4B)
 Protocol ID Type(2B)
```
여기서 Type에 따라서 L4패킷이 정해지는데 1은 ICMP, 2는 IGMP, 17은 UDP(스타크래프트), 6이 TCP이므로 6일때만 또 진행하면 된다.

**TCP** 는 이름만 많이 듣고 써본적은 없다. L4 계층인 것만 알면 될 것 같다. UDP와 헤더구조가 어느정도 유사하다.

TCP header
```
 총 20 Byte
 Destination Port Number(2B)
 Source Port Number(2B)
```

이정도인데 위의 정보만 보면 단순히 구조체에서 구조체로 넘어가 출력하는 과제이다. C언어야 1년 반동안 공부한 내용이니 형식만 알면 쉬울 것 같다.

## + @
수업시간 코드리뷰 정보 (과제시 참고)

- ntohs(), ntohl() 등의 함수 사용

- 구조체 헤더 만들기 (파일의 가독성을 위해, 또한 구조체 자체는 이미 많은 자료 존재)

- indent 주의 (tab사용 최소화, 이건 기본이니까 하던대로만 하면될 듯)

- 반복되는 부분은 함수 사용 (해보니까 반복되는 부분이 거의 없다)

- 매크로 상수의 사용 (2번 이상 나오는 상수들은 상수 저장)

- pcap 구조 이해하기 (익숙하지 않으므로)

- git 익숙해지기
