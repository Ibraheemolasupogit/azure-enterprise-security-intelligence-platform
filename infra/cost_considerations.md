# Cost Considerations

This document highlights cost areas for a future Azure implementation. It does not estimate real
charges or require cloud resources.

## Main Cost Drivers

- Microsoft Sentinel and Log Analytics ingestion volume
- Log retention duration and archive requirements
- Azure Data Lake Storage capacity and transaction volume
- Azure Data Explorer cluster sizing and query workload
- Event Hub throughput units or premium capacity
- Power BI or Microsoft Fabric licensing and capacity
- Azure Machine Learning compute for future model workflows
- Azure AI Foundry, Azure OpenAI, and Azure AI Search for future investigation workflows

## Cost Optimisation Options

- Filter low-value telemetry before ingestion where policy allows.
- Use table-level retention policies in Log Analytics.
- Archive older logs to lower-cost storage tiers.
- Use ADLS lifecycle management for raw and curated zones.
- Start with serverless or small analytics footprints before scaling.
- Separate dev, test, and prod retention and capacity settings.

## Sentinel And Log Analytics Awareness

Sentinel and Log Analytics costs are strongly influenced by daily ingestion volume and retention.
Production design should define source prioritisation, transformation rules, retention tiers, and
dashboard query patterns before broad onboarding.

## Storage Lifecycle Management

Raw security data should have clear hot, cool, archive, and deletion policies. Evidence artifacts may
need longer retention than temporary analytics extracts, depending on compliance requirements.

## Dashboard And Reporting Costs

Power BI, Microsoft Fabric, and Sentinel workbooks should use curated data products and efficient
queries. Executive dashboards should avoid repeatedly scanning high-volume raw telemetry.

