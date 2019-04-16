import React, { Component } from "react";
import { Link } from "react-router-dom";
import { Layout, Table } from "antd";

const { Content, Header } = Layout;

const columnsResults = [
  {
    title: "ID",
    dataIndex: "task_id",
    width: 450,
    render: text => (
      <Link to={"/result/" + text}>
        <code>{text}</code>
      </Link>
    )
  },
  {
    title: "File",
    render: (text, record) => <span>{record.result.filename}</span>
  },
  {
    title: "Time",
    dataIndex: "date_done",
    width: 350
  }
];

class ResultsPage extends Component {
  constructor(props) {
    super(props);

    this.state = {
      results: []
    };
  }

  componentDidMount() {
    this.loadResults();
  }

  loadResults = () => {
    fetch("http://" + process.env.REACT_APP_HOST + "/api/tasks/finished")
      .then(res => res.json())
      .then(results => {
        console.log(results);
        if (!results.hasOwnProperty("error")) {
          this.setState({ results });
        }
      })
      .catch(error => {
        console.log(error);
      });
  };

  render() {
    let pagination = { pageSize: 20, size: "small" };

    return (
      <Layout style={{ marginLeft: 200 }}>
        <Header className="header">
          <h2 className="header-headline">Results</h2>
        </Header>
        <Content className="page-content">
          <div className="inner-page-content">
            <Table
              columns={columnsResults}
              dataSource={this.state.results}
              pagination={pagination}
              rowKey="task_id"
            />
          </div>
        </Content>
      </Layout>
    );
  }
}

export default ResultsPage;
