creator = "Kartavya Trivedi"
projectLocation = "https://github.com/Jistrokz/TheSweeper"

import os
import TheSweeperCommonFunctions

ReportElement = """
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
         <img src="./logo.png" alt="TheSweeper Logo">
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
         <br><br><br>
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

def GenerateReport(MatchesList):
    """
      Generates an html report for files that has a match with Yara-Rules
      :param matches_list: list of dictionaries containing match details for each file. example {"file": FilePath, "YaraRulesFile": RulePath, "MatchList": matches}
      :return: list of dictionaries containing match details for each file
      """
    ReportTitle = 'TheSweeper - Scan Report'
    ReportDateTime = TheSweeperCommonFunctions.GetDatetime()

    report = ReportTemplate.replace('%REPORT_TITLE%', ReportTitle)
    report = report.replace('%REPORT_DATE_TIME%', ReportDateTime)

    TableContent = ""

    index = 1
    for match in MatchesList:
        if match is None:
            continue

        element = ReportElement.replace('%INDEX%', str(index))
        element = element.replace('%FILE_PATH%', match['file'])

        MatchesStr =  YaraMatchListToString(match['MatchList'])

        RuleFileName = ''
        if os.path.isfile(match['YaraRulesFile']):
            RuleFileName = os.path.basename(match['YaraRulesFile'])


        element = element.replace('%MATCHES%', MatchesStr)
        element = element.replace('%YARA_RULES_FILE_NAME%', RuleFileName)
        TableContent += element
        index += 1

    report = report.replace('%TABLE_CONTENT%', TableContent)
    return report