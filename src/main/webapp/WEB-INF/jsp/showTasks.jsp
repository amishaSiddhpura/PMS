<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@page session="true"%>
<html>
<head>
    <title>Show Projects</title>
    <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
</head>
<body>
<jsp:include page="menu.jsp" />
<center>
<h1 style="color: red; text-align: center">Show All Tasks</h1>

    <table class="w3-table-all w3-card-4"style="text-align: center">
        <tr>
            <th style="text-align: center">Task ID</th>
            <th style="text-align: center">TITLE</th>
            <th style="text-align: center">Project</th>
            <th style="text-align: center">DESCRIPTION</th>
            <th style="text-align: center">Deadline</th>
            <th style="text-align: center">State</th>
            <th style="text-align: center">EDIT</th>
            <th style="text-align: center">DELETE</th>
        </tr>
        <c:forEach var="listValue" items="${task}">
            <tr>
                <td style="text-align: center">${listValue.id}</td>
                <td style="text-align: center">${listValue.title}</td>
                <td style="text-align: center">${listValue.project}</td>
                <td style="text-align: center">${listValue.description}</td>
                <td style="text-align: center">${listValue.deadline}</td>
                <td style="text-align: center">${listValue.state}</td>
                <td style="text-align: center"><a href="/editTask?id=${listValue.id}">Edit</a> </td>
                <td  style="text-align: center"><a href="/deleteTask?id=${listValue.id}">Delete</a> </td>
            </tr>
        </c:forEach>
    </table>

</center>
</body>
</html>