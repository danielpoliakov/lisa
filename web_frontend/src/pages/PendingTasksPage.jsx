import React, { Component } from "react";
import { Layout, Table } from "antd";

const { Content, Header } = Layout;

const columnsTasks = [
  {
    title: "ID",
    dataIndex: "id",
    width: 450,
    render: text => <code>{text}</code>
  },
  {
    title: "File",
    render: (text, record) => (
      <span>
        {record.args
          .split("/")
          .pop()
          .split(",")
          .slice(0, -1)[0]
          .slice(0, -1)}
      </span>
    )
  }
];

class PendingTasksPage extends Component {
  constructor(props) {
    super(props);

    this.state = {
      workers: {}
    };
  }

  componentDidMount() {
    this.loadTasks();
  }

  loadTasks = () => {
    fetch("http://" + process.env.REACT_APP_HOST + "/api/tasks/pending")
      .then(res => res.json())
      .then(workers => {
        console.log(workers);
        if (!workers.hasOwnProperty("error")) {
          this.setState({ workers });
        }
      })
      .catch(error => {
        console.log(error);
      });
  };

  render() {
    const pagination = { pageSize: 10, size: "small" };
    const { workers } = this.state;

    let tables = [];

    for (let worker in workers) {
      console.log(workers[worker]);
      const workerSection = (
        <div className="workerSection" key={worker}>
          <h3 className="report-section-headline">{worker}</h3>
          <Table
            columns={columnsTasks}
            dataSource={workers[worker]}
            pagination={pagination}
            rowKey="id"
          />
        </div>
      );
      tables.push(workerSection);
    }

    return (
      <Layout style={{ marginLeft: 200 }}>
        <Header className="header">
          <h2 className="header-headline">Pending tasks</h2>
        </Header>
        <Content className="page-content">
          <div className="inner-page-content">{tables}</div>
        </Content>
      </Layout>
    );
  }
}

export default PendingTasksPage;
