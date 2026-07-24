"""
    Generates a formatted PDF from a LiSa report.json file.
"""
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name='SectionHeader', fontSize=14, spaceAfter=10,
                           spaceBefore=16, textColor=colors.HexColor('#1a1a2e'),
                           fontName='Helvetica-Bold'))
styles.add(ParagraphStyle(name='SubHeader', fontSize=11, spaceAfter=6,
                           spaceBefore=10, textColor=colors.HexColor('#333355'),
                           fontName='Helvetica-Bold'))
styles.add(ParagraphStyle(name='SmallMono', fontSize=7, fontName='Courier',
                           leading=9))

MAX_LIST_ITEMS = 200  # cap very long lists (e.g. strings, syscalls) for readability


def _fmt(value):
    """Safely stringify a value for table cells."""
    if value is None:
        return '-'
    if isinstance(value, bool):
        return 'yes' if value else 'no'
    return str(value)


def _dict_table(d):
    """Render a flat dict as a two-column key/value table."""
    if not d:
        return Paragraph('(empty)', styles['Normal'])
    rows = [[Paragraph(f'<b>{k}</b>', styles['Normal']),
             Paragraph(_fmt(v), styles['Normal'])] for k, v in d.items()]
    table = Table(rows, colWidths=[4 * cm, 12 * cm])
    table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f5')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
    ]))
    return table


def _list_of_dicts_table(items):
    """Render a list of dicts as a table using the union of keys as columns."""
    if not items:
        return Paragraph('(none)', styles['Normal'])

    items = items[:MAX_LIST_ITEMS]
    keys = []
    for item in items:
        if isinstance(item, dict):
            for k in item.keys():
                if k not in keys:
                    keys.append(k)

    if not keys:
        # plain list of scalars
        return _string_list(items)

    header = [Paragraph(f'<b>{k}</b>', styles['Normal']) for k in keys]
    rows = [header]
    for item in items:
        if isinstance(item, dict):
            rows.append([Paragraph(_fmt(item.get(k, '')), styles['SmallMono'])
                         for k in keys])
        else:
            rows.append([Paragraph(_fmt(item), styles['SmallMono'])] +
                        [''] * (len(keys) - 1))

    table = Table(rows, repeatRows=1)
    table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dcdcf0')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
    ]))
    return table


def _string_list(items):
    """Render a plain list of strings/scalars as monospace paragraphs."""
    if not items:
        return Paragraph('(none)', styles['Normal'])
    items = items[:MAX_LIST_ITEMS]
    text = '<br/>'.join(_fmt(i).replace('<', '&lt;').replace('>', '&gt;')
                         for i in items)
    note = ''
    if len(items) == MAX_LIST_ITEMS:
        note = f'<br/><i>... truncated at {MAX_LIST_ITEMS} items</i>'
    return Paragraph(text + note, styles['SmallMono'])


def _render_value(value):
    """Dispatch a JSON value to the right renderer."""
    if isinstance(value, dict):
        return _dict_table(value)
    if isinstance(value, list):
        if value and isinstance(value[0], dict):
            return _list_of_dicts_table(value)
        return _string_list(value)
    return Paragraph(_fmt(value), styles['Normal'])


def _render_section(title, data):
    """Render a top-level report section (e.g. static_analysis) with subheaders."""
    story = [Paragraph(title, styles['SectionHeader'])]
    if isinstance(data, dict):
        for key, value in data.items():
            story.append(Paragraph(key.replace('_', ' ').title(),
                                    styles['SubHeader']))
            story.append(_render_value(value))
            story.append(Spacer(1, 6))
    else:
        story.append(_render_value(data))
    return story


def generate_pdf(report_data, output_path):
    """Build a PDF file from a LiSa report.json dict.

    :param report_data: Parsed report.json contents (dict).
    :param output_path: Filesystem path to write the PDF to.
    """
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        topMargin=1.5 * cm, bottomMargin=1.5 * cm,
        leftMargin=1.5 * cm, rightMargin=1.5 * cm,
    )
    story = []

    # --- Summary section ---
    story.append(Paragraph('LiSa Analysis Report', styles['Title']))
    story.append(Spacer(1, 12))

    summary_keys = ['file_name', 'type', 'exec_time', 'timestamp',
                     'analysis_start_time', 'md5', 'sha1', 'sha256']
    summary = {k: report_data.get(k) for k in summary_keys if k in report_data}
    story.append(_dict_table(summary))
    story.append(Spacer(1, 12))

    # --- Main sections ---
    section_order = ['static_analysis', 'dynamic_analysis', 'network_analysis']
    for section in section_order:
        if section in report_data:
            story.append(PageBreak())
            story.extend(_render_section(
                section.replace('_', ' ').title(), report_data[section]
            ))

    # any remaining top-level keys not already covered
    covered = set(summary_keys) | set(section_order)
    extras = {k: v for k, v in report_data.items() if k not in covered}
    if extras:
        story.append(PageBreak())
        story.extend(_render_section('Other', extras))

    doc.build(story)
