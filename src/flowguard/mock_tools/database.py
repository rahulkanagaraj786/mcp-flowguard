from mcp.server.fastmcp import FastMCP

CANNED_RESULTS = {
    "employees": "id,name,email,ssn,salary\n1,Alice Smith,alice@corp.com,123-45-6789,150000\n2,Bob Jones,bob@corp.com,987-65-4321,120000",
    "customers": "id,name,email,credit_card\n1,Dave Brown,dave@example.com,4111-1111-1111-1111",
    "public_data": "id,title,description\n1,Public Report Q4,Quarterly summary for public release\n2,Product Catalog,List of available products",
    "audit_logs": "timestamp,user,action\n2024-01-01 10:00:00,admin,login\n2024-01-01 10:05:00,alice,read_file",
}


def create_database_server() -> FastMCP:
    server = FastMCP(name="database")

    @server.tool()
    def query(sql: str) -> str:
        """Execute a SQL query and return results."""
        sql_lower = sql.lower()
        for table_name, result in CANNED_RESULTS.items():
            if table_name in sql_lower:
                return result
        return "id,result\n(empty result set)"

    @server.tool()
    def insert(table: str, data: str) -> str:
        """Insert data into a table."""
        return f"INSERT into {table}: 1 row affected"

    return server
