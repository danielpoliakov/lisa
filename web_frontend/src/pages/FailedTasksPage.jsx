import React, { Component } from "react";
import { Layout, Table } from "antd";

const { Content, Header } = Layout;

const columnsErrors = [
  {
    title: "ID",
    dataIndex: "task_id",
    width: 450,
    render: text => <code>{text}</code>
  },
  {
    title: "File",
    render: (text, record) => <span>{record.result.filename}</span>
  },
  {
    title: "Time",
    dataIndex: "date_done"
  },
  {
    title: "Error Type",
    render: (text, record) => <span>{record.result.exc_type}</span>
  }
];

class FailedTasksPage extends Component {
  constructor(props) {
    super(props);

    this.state = {
      tasks: []
    };
  }

  componentDidMount() {
    this.loadTasks();
  }

  loadTasks = () => {
    fetch("http://" + process.env.REACT_APP_HOST + "/api/tasks/failed")
      .then(res => res.json())
      .then(tasks => {
        console.log(tasks);
        if (!tasks.hasOwnProperty("error")) {
          this.setState({ tasks });
        }
      })
      .catch(error => {
        console.log(error);
      });
  };

  tracebackRenderer = task => {
    return <code className="code-data">{task.result.traceback}</code>;
  };

  render() {
    let pagination = { pageSize: 20, size: "small" };
    return (
      <Layout style={{ marginLeft: 200 }}>
        <Header className="header">
          <h2 className="header-headline">Failed tasks</h2>
        </Header>
        <Content className="page-content">
          <div className="inner-page-content">
            <Table
              columns={columnsErrors}
              dataSource={this.state.tasks}
              pagination={pagination}
              expandedRowRender={this.tracebackRenderer}
              rowKey="task_id"
            />
          </div>
        </Content>
      </Layout>
    );
  }
}

export default FailedTasksPage;
