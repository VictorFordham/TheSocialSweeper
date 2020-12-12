creator = "Kartavya Trivedi"
projectLocation = "https://github.com/Jistrokz/TheSweeper"

import os
import TheSweeperCommonFunctions

report_element = """
    <tr>
        <td align="center">
           <font face="Arial, Helvetica, sans-serif">%INDEX%</font>
        </td>
        <td align="center">
           <font face="Arial, Helvetica, sans-serif">%FILE_PATH% </font>
        </td>
        <td align="center">
           <font face="Arial, Helvetica, sans-serif">%MATCHES%</font>
        </td>
        <td align="center">
           <font face="Arial, Helvetica, sans-serif">%YARA_RULES_FILE_NAME%</font>
        </td>
    </tr>
"""

ReportTemplate = """
<html>
   <head>
      <title>%REPORT_TITLE% - %REPORT_DATE_TIME%</title>
      <style>
         table
         {
         border-bottom: 1px Solid Black;         
         border-right: 1px Solid Black;         
         border-collapse : collapse;  
         }
         table td, table th  
         {    
         border-left: 1px Solid Black;         
         border-top: 1px Solid Black;              
         border-bottom:none;    
         border-right:none;
         max-width: 550px;
         word-wrap: break-word;
         }
      </style>
   </head>
   <body>
      <center>
         <img src="./logo.png>
         <h2>%REPORT_TITLE%</h2>
         <h3>%REPORT_DATE_TIME%</h3>
         <table border="1" cellspacing="2" cellpadding="2">
            <tr>
               <td align="center", style="font-weight: bold;">
                  <font face="Arial, Helvetica, sans-serif"></font>
               </td>
               <td align="center", style="font-weight: bold;">
                  <font face="Arial, Helvetica, sans-serif">File Path</font>
               </td>
               <td align="center", style="font-weight: bold;">
                  <font face="Arial, Helvetica, sans-serif">Rules Matched</font>
               </td>
               <td align="center", style="font-weight: bold;">
                  <font face="Arial, Helvetica, sans-serif">Yara Rules</font>
               </td>
            </tr>
               %TABLE_CONTENT%
         </table>
      </center>
   </body>
</html>
"""

def YaraMatchListToString(YaraMathes):
    text = ''
    for x in YaraMathes:
        text += str(x) + ', '

    text = text.rstrip(' ')
    text = text.rstrip(',')
    text = '[{}]'.format(text)
    return text

def generate_report(MatchesList):
    """
      Generates an html report for files that has a match with Yara-Rules
      :param matches_list: list of dictionaries containing match details for each file. example {"file": file_path, "yara_rules_file": rule_path, "match_list": matches}
      :return: list of dictionaries containing match details for each file
      """
    ReportTitle = 'TheSweeper - Scan Report'
    ReportDateTime = TheSweeperCommonFunctions.GetDatetime()

    report = ReportTemplate.replace('%REPORT_TITLE%', ReportTitle)
    report = report.replace('%REPORT_DATE_TIME%', ReportDateTime)

    table_content = ""

    index = 1
    for match in MatchesList:
        if match is None:
            continue

        element = ReportElement.replace('%INDEX%', str(index))
        element = element.replace('%FILE_PATH%', match['file'])

        matches_str =  YaraMatchListToString(match['MatchList'])

        rule_file_name = ''
        if os.path.isfile(match['YaraRulesFile']):
            rule_file_Name = os.path.basename(match['YaraRulesFile'])


        element = element.replace('%MATCHES%', matches_str)
        element = element.replace('%YARA_RULES_FILE_NAME%', rule_file_name)
        table_content += element
        index += 1

    report = report.replace('%TABLE_CONTENT%', table_content)
    return report