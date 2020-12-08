<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@ taglib prefix="font" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@page session="true"%>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <title>Add User</title>
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
    .error{
    color:red;
    text-align:center;
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

<c:if test="${user.username ne null}">
<h1 style="color: red;">Edit User</h1>
</c:if>
<c:if test="${user.username eq null}">
<h1 style="color: red;">Add New User</h1>
</c:if>

<div id="addEmployee">

    <table class="content-table"style="text-align: center">
    <form:form action="/addUser" method="post" modelAttribute="user">
        <form:hidden path="id" value = "${user.id}" name="id" />
            <tr class="error"><td>${error}</td></tr>
            <tr>
                <td><label>Enter Username${user.id}</label></td>
                <td><form:input path="username" value="${user.username}" required="true" /></td>
            </tr>
        <c:if test="${user.username eq null}">
            <tr>
                <td>Enter password</td>
                <td><form:password path="password" required="true" /></td>
            </tr>
        </c:if>
            <tr>
                <td><label>Select Role</label></td>
                <td><form:select path="role" selected="${user.role}">
                    <font:option value="ROLE_ADMIN">ROLE_ADMIN</font:option>
                    <font:option value="ROLE_LEADER">ROLE_LEADER</font:option>
                    <font:option value="ROLE_MEMBER">ROLE_MEMBER</font:option>
                </form:select></td>
            </tr>
        <tr>
            <td colspan=2 style="text-align:center;"><c:if test="${user.username eq null}">
                <input type="SUBMIT" class="button" value="Submit" name="SUBMIT" />
            </c:if>
                <c:if test="${user.username ne null}">
                    <input type="SUBMIT" class="button" value="Update" name="SUBMIT" />
                </c:if></td>
        </tr>
        </table>
    </form:form>
</div>
</center>
</body>
</html>




