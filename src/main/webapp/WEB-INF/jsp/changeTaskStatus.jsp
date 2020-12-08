<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@ taglib prefix="font" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@page session="true"%>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <title>Change Status</title>
    <style>
        *{ font-family: 'Quicksand', sans-serif;}

        .content-table{
            border-collapse: collapse;
            margin: 25px 0;
            font-size: 0.9em;
            min-width: 400px;
            border-radius: 5px 5px 0 0;
            overflow: hidden;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.15)
        }

        .content-table thead tr{
            background-color: #009879;
            color: white;
            text-align: left;
            font-weight: bold;
        }
        .content-table th, .content-table td{
            padding: 12px 15px;
        }
        .content-table tbody tr{
            border-bottom: 1px solid #dddddd;
        }
        .content-table tbody tr:nth-of-type(even){
            background-color: #f3f3f3;
        }
        .content-table tbody tr:last-of-type{
            border-bottom: 2px solid #00a2ff;
        }
        .button {
            border-radius: 4px;
            background-color: #f4511e;
            border: none;
            color: #FFFFFF;
            text-align: center;
            font-size: 15px;
            padding: 20px;
            width: 100px;
            height: 5px;
            transition: all 0.5s;
            cursor: pointer;
            margin: 5px;
            padding-top: 9px;
            padding-bottom: 25px;
        }
        .button {
            border-radius: 4px;
            background-color: #f4511e;
            border: none;
            color: #FFFFFF;
            text-align: center;
            font-size: 15px;
            padding: 20px;
            width: 100px;
            height: 5px;
            transition: all 0.5s;
            cursor: pointer;
            margin: 5px;
            padding-top: 9px;
            padding-bottom: 25px;
        }
    </style>
</head>
<jsp:include page="menu.jsp" />
<body>
<center>
    <h1 style="color: red;">Change Status</h1>

    <div id="addProject">
        <table class="content-table" style="text-align: center">
            <%--@elvariable id="task" type="com.mcit.pms.model.Task"--%>
            <form:form action="updateStatus" method="post" modelAttribute="task">
            <form:hidden path="id" value = "${id}" name="id" />
            <tr>
                <td><label>Status</label></td>
                    <td><form:select path="state">
                        <form:option value="Pending">Pending</form:option>
                        <form:option value="To-DO">To Do</form:option>
                        <form:option value="Completed">Completed</form:option>
                    </form:select>
            </tr>
            <tr>
                <td colspan="2" style="text-align:center;">
                    <input type="SUBMIT" class="button" value="Update" name="SUBMIT" /></td>
                </form:form>
            </tr>
        </table>
    </div>
</center>
</body>
</html>
