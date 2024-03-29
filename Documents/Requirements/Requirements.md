# ���������� � �������
---

# ����������
1 [��������](#intro)  
1.1 [����������](#appointment)  
1.2 [������-����������](#business_requirements)  
1.2.1 [�������� ������](#initial_data)  
1.2.2 [����������� �������](#business_opportunities)  
1.2.3 [������� �������](#project_boundary)

2 [���������� ������������](#user_requirements)  
2.1 [����������� ����������](#software_interfaces)  
2.2 [��������� ������������](#user_interface)  
2.4 [������������� � �����������](#assumptions_and_dependencies)  
3 [��������� ����������](#system_requirements)  
3.1 [�������������� ����������](#functional_requirements)  
3.1.1 [�������� �������](#main_functions)  
3.1.1.1 [����� ���������� � ����������� �������� �������](#information_output)

3.1.2 [����������� � ����������](#restrictions_and_exclusions)  
3.2 [���������������� ����������](#non-functional_requirements)  
3.2.1 [�������� ��������](#quality_attributes)  
3.2.2 [������� ����������](#external_interfaces)  
3.2.3 [�����������](#restrictions)  

<a name="intro"/>

# 1 ��������
�������� �������: "NTFS_check".

���������� ������������� ��� �������� ������������ ����������, ��������� ��������� �������� ����������� �������� ������� NTFS.

<a name="appointment"/>

## 1.1 ����������
� ���� ��������� ������� �������������� � ���������������� ���������� � ���������� �NTFS_check"� ��� �� Windows 10. ���� �������� ������������ ��� �������, ������� ����� ������������� � ��������� ������������ ������ ����������. 

<a name="business_requirements"/>

## 1.2 ������-����������

<a name="initial_data"/>

### 1.2.1 �������� ������
� ������ ����� ��������� ��������, ����� �� ���������� ���� ��� ��������� ������ �����������, ����� ��������� ��������������� ����������� ��� �������� ��� �������� ����������� �������� �������.

<a name="business_opportunities"/>

### 1.2.2 ����������� �������
������ ������������ ������ ����������� ����� ����������, ������� �������� �������� ����������� �������� �������, ������� ���������� ����������� ������������. �������� ���������� �������� �� ������� ������ ������� �� ����� ����������� ������.

<a name="project_boundary"/>

### 1.2.3 ������� �������
���������� �NTFS_check� �������� ������������� ������������� ���������� � ��������� �������� ������� NTFS.

<a name="user_requirements"/>

# 2 ���������� ������������

<a name="user_interfaces"/>

## 2.1 ��������� ������������

## ���� ������ ����������.
 
![���� ������ ����������](./../../Images/Mockups/application_output_window.png)

<a name="application_audience"/>

### 2.2 ��������� ����������

���������� ������� ���������� �������� ������������ �����������.

<a name="system_requirements"/>

# 3 ��������� ����������

<a name="functional_requirements"/>

## 3.1 �������������� ����������

<a name="main_functions"/>

### 3.1.1 �������� �������

<a name="information_output"/>

#### 3.1.1.1 ����� ���������� � ����������� �������� �������

| ������� | ���������� | 
|:---|:---|
| �������� ���������� | ���������� ������ ������������ ������������ ����������� ��������� ����������� ���� ������ ���������� ���������� |
| <a name="registration_requirements"/>�������� ���� ������ ���������� ����� | ���������� ������ ������������ ������������ ����������� ��������� ����������� ���� ������ ���������� ����� |

<a name="non-functional_requirements"/>

## 3.2 ���������������� ����������

<a name="quality_attributes"/>

### 3.2.1 �������� ��������
1. ��������� ���������� ������������� �������� ������� ���������� ���������� � �������.

<a name="external_interfaces"/>

### 3.2.2 ������� ����������
���� ���������� ������ ��� ������������� �������������� � ������ �������:
  * ������ ������ �� ����� 14��;
  * �������������� �������� ���������� ���� ����.
  * ���� ���������� �������

<a name="restrictions"/>

### 3.2.3 �����������
1. ���������� ����������� ��� �������� ������� NFTS ������������ ������� Windows 10 � �������������� ����� C++.