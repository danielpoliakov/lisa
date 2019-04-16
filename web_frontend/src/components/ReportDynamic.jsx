import React, { Component } from "react";
import { List, Table, Tree } from "antd";

const { TreeNode } = Tree;

const columnsSyscalls = [
  {
    title: "Syscall",
    dataIndex: "name",
    width: 200
  },
  {
    title: "Arguments",
    dataIndex: "arguments"
  },
  {
    title: "Return",
    dataIndex: "return",
    width: 200
  }
];

class ReportStatic extends Component {
  constructor(props) {
    super(props);

    const r = this.props.report;

    this.openFiles = r.open_files;

    this.syscalls = [];
    for (let i = 0; i < r.syscalls.length; i++) {
      this.syscalls.push({
        key: i,
        name: r.syscalls[i].name,
        arguments: r.syscalls[i].arguments,
        return: r.syscalls[i].return
      });
    }

    this.processTreeNodes = this.parseProcessFirst();
  }

  parseProcessFirst = () => {
    const processes = this.props.report.processes;
    let nodes;

    if (processes.length !== 0) {
      let pid = processes[0].pid;
      nodes = (
        <TreeNode title={"PID: " + pid.toString()} key={pid.toString()}>
          {this.parseProcessesWithParent(pid)}
        </TreeNode>
      );
    }

    return nodes;
  };

  parseProcessesWithParent = parentPID => {
    const processes = this.props.report.processes;
    let nodes = [];

    for (let i = 0; i < processes.length; i++) {
      let pid = processes[i].pid;
      let parent = processes[i].parent;

      if (parent === parentPID) {
        let node = (
          <TreeNode title={"PID: " + pid.toString()} key={pid.toString()}>
            {this.parseProcessesWithParent(pid)}
          </TreeNode>
        );
        nodes.push(node);
      }
    }

    return nodes;
  };

  render() {
    let pagination = { pageSize: 10, size: "small" };

    let filesPagination = this.openFiles.length === 0 ? false : pagination;

    return (
      <div className="report-part">
        <h3 className="report-section-headline">Process tree</h3>

        <Tree defaultExpandAll className="process-tree">
          {this.processTreeNodes}
        </Tree>

        <h3 className="report-section-headline">Opened files</h3>

        <List
          dataSource={this.openFiles}
          renderItem={item => <List.Item>{item}</List.Item>}
          pagination={filesPagination}
        />

        <h3 className="report-section-headline">Syscalls</h3>

        <Table
          columns={columnsSyscalls}
          dataSource={this.syscalls}
          pagination={pagination}
        />
      </div>
    );
  }
}

export default ReportStatic;
