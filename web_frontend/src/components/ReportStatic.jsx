import React, { Component } from "react";
import { List, Table } from "antd";

const columnsElfInfo = [
  {
    title: "Key",
    dataIndex: "key",
    render: text => <b>{text}</b>,
    width: 180
  },
  {
    title: "Value",
    dataIndex: "value"
  }
];

const columnsImports = [
  {
    title: "Name",
    dataIndex: "name"
  },
  {
    title: "Type",
    dataIndex: "type",
    width: 180
  },
  {
    title: "Bind",
    dataIndex: "bind",
    width: 180
  }
];

const columnsExports = [
  {
    title: "Name",
    dataIndex: "flagname"
  },
  {
    title: "Virt. Addr",
    dataIndex: "vaddr",
    width: 180
  },
  {
    title: "Phys. Addr",
    dataIndex: "paddr",
    width: 180
  },
  {
    title: "Type",
    dataIndex: "type",
    width: 180
  },
  {
    title: "Bind",
    dataIndex: "bind",
    width: 180
  }
];

const columnsRelocations = [
  {
    title: "Name",
    dataIndex: "name"
  },
  {
    title: "Virt. Addr",
    dataIndex: "vaddr",
    width: 180
  },
  {
    title: "Phys. Addr",
    dataIndex: "paddr",
    width: 180
  },
  {
    title: "Type",
    dataIndex: "type",
    width: 180
  }
];

const columnsSymbols = [
  {
    title: "Name",
    dataIndex: "name"
  },
  {
    title: "Virt. Addr",
    dataIndex: "vaddr",
    width: 180
  },
  {
    title: "Phys. Addr",
    dataIndex: "paddr",
    width: 180
  },
  {
    title: "Bind",
    dataIndex: "bind",
    width: 180
  },
  {
    title: "Type",
    dataIndex: "type",
    width: 180
  }
];

const columnsSections = [
  {
    title: "Name",
    dataIndex: "name"
  },
  {
    title: "Virt. Addr",
    dataIndex: "vaddr",
    width: 180
  },
  {
    title: "Phys. Addr",
    dataIndex: "paddr",
    width: 180
  },
  {
    title: "Size",
    dataIndex: "size",
    width: 180
  },
  {
    title: "Permissions",
    dataIndex: "perm",
    width: 180
  }
];

class ReportStatic extends Component {
  constructor(props) {
    super(props);

    const r = this.props.report;

    this.elfInfo = [
      {
        key: "Architecture",
        value: r.binary_info.arch
      },
      {
        key: "Endianess",
        value: r.binary_info.endianess
      },
      {
        key: "Machine",
        value: r.binary_info.machine
      },
      {
        key: "Type",
        value: r.binary_info.type
      },
      {
        key: "Size",
        value: r.binary_info.size
      },
      {
        key: "OS",
        value: r.binary_info.os
      },
      {
        key: "Static",
        value: r.binary_info.static.toString()
      },
      {
        key: "Interpret",
        value: r.binary_info.interpret
      },
      {
        key: "Stripped",
        value: r.binary_info.stripped.toString()
      },
      {
        key: "Relocations",
        value: r.binary_info.relocations.toString()
      },
      {
        key: "Min opsize",
        value: r.binary_info.min_opsize
      },
      {
        key: "Max opsize",
        value: r.binary_info.max_opsize
      },
      {
        key: "Entrypoint",
        value: r.binary_info.entry_point
      }
    ];

    this.imports = r.imports;

    this.exports = r.exports;

    this.libs = r.libs;

    let relocs = r.relocations;
    this.relocations = [];
    for (let i = 0; i < relocs.length; i++) {
      this.relocations.push({
        key: i,
        name: relocs[i].name,
        type: relocs[i].type,
        vaddr: relocs[i].vaddr,
        paddr: relocs[i].paddr
      });
    }

    this.symbols = r.symbols;

    let secs = r.sections;
    this.sections = [];
    for (let i = 0; i < secs.length; i++) {
      this.sections.push({
        key: i,
        name: secs[i].name,
        size: secs[i].size,
        vaddr: secs[i].vaddr,
        paddr: secs[i].paddr,
        perm: secs[i].perm
      });
    }

    this.strings = r.strings;
  }

  render() {
    const pagination = { pageSize: 5, size: "small" };

    const libsPagination = this.libs.length === 0 ? false : pagination;
    const stringsPagination = this.strings.length === 0 ? false : pagination;

    return (
      <div className="report-part">
        <h3 className="report-section-headline">ELF info</h3>

        <Table
          columns={columnsElfInfo}
          dataSource={this.elfInfo}
          pagination={false}
          showHeader={false}
          className="table-no-pagination"
        />

        <h3 className="report-section-headline">Imports</h3>

        <Table
          columns={columnsImports}
          dataSource={this.imports}
          pagination={pagination}
          rowKey="ordinal"
        />

        <h3 className="report-section-headline">Exports</h3>

        <Table
          columns={columnsExports}
          dataSource={this.exports}
          pagination={pagination}
          rowKey="ordinal"
        />

        <h3 className="report-section-headline">Libraries</h3>

        <List
          dataSource={this.libs}
          renderItem={item => <List.Item>{item}</List.Item>}
          pagination={libsPagination}
        />

        <h3 className="report-section-headline">Relocations</h3>

        <Table
          columns={columnsRelocations}
          dataSource={this.relocations}
          pagination={pagination}
        />

        <h3 className="report-section-headline">Symbols</h3>

        <Table
          columns={columnsSymbols}
          dataSource={this.symbols}
          pagination={pagination}
          rowKey="ordinal"
        />

        <h3 className="report-section-headline">Sections</h3>

        <Table
          columns={columnsSections}
          dataSource={this.sections}
          pagination={pagination}
        />

        <h3 className="report-section-headline">Strings</h3>

        <List
          dataSource={this.strings}
          renderItem={item => <List.Item>{item}</List.Item>}
          pagination={stringsPagination}
        />
      </div>
    );
  }
}

export default ReportStatic;
