<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@ taglib prefix="font" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@page session="true"%>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <title>Add Project</title>
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
<c:if test="${project.id ne null}">
<h1 style="color: red;">Edit Project</h1>
</c:if>
<c:if test="${project.id eq null}">
<h1 style="color: red;">Add New Project</h1>
</c:if>

<div id="addProject">
    <table class="content-table" style="text-align: center">
    <%--@elvariable id="project" type="com.mcit.pms.model.Project"--%>
    <form:form action="addNewProject" method="post" modelAttribute="project">
        <form:hidden path="id" value = "${project.id}" name="id" />
        <tr>
            <td><label>Project Title</label></td>
            <td><form:input path="title" value="${project.title}" required="true" /></td>
        </tr>
            <tr>
             <td><label>Description</label></td>
             <td><form:input path="description" value="${project.description}" required="true" /></td>
            </tr>
        <tr>
             <td><label>Start Date</label></td>
             <td><form:input type="date"  path="startDate" value="${project.startDate}" required="true" /></td>
        </tr>
        <tr>
            <td><label>End Date</label></td>
            <td><form:input type="date" path="endDate" value="${project.endDate}" required="true" /></td>
        </tr>
        <tr>
        <td colspan="2" style="text-align:center;"><c:if test="${project.id eq null}">
            <input type="SUBMIT" class="button" value="Submit" name="SUBMIT" /></td>
        </c:if>
        <c:if test="${project.id ne null}">
            <input type="SUBMIT" class="button" value="Update" name="SUBMIT" /></td>
        </c:if></td>
    </form:form>
        </tr>
    </table>
</div>
</center>
</body>
</html>
