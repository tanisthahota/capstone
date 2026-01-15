import pandas as pd
import json
import os

# Define the files to process and their corresponding labels
FILES_TO_PROCESS = {
    "benign": "benign_events.jsonl",
    "reverse_shell": "reverse_shell_events.jsonl",
    "priv_esc": "priv_esc_events.jsonl"
}

# This will hold a list of all our processed data (as DataFrames)
all_data_frames = []

print("Starting dataset processing...")

# Loop through each file, read it, and add the label
for label, filename in FILES_TO_PROCESS.items():
    if not os.path.exists(filename):
        print(f"⚠️ Warning: File '{filename}' not found. Skipping.")
        continue

    try:
        # pd.read_json with lines=True is the perfect tool for .jsonl files
        df = pd.read_json(filename, lines=True)
        
        # Add the all-important 'label' column
        df['label'] = label
        
        all_data_frames.append(df)
        print(f"✅ Processed {filename} (found {len(df)} events)")
        
    except Exception as e:
        print(f"❌ Error processing {filename}: {e}")
        print("   This can happen if the file is empty or malformed. Skipping.")

# Check if we actually processed any data
if not all_data_frames:
    print("\n❌ No data was processed. Please check your .jsonl files.")
else:
    # Combine all the individual DataFrames into one master DataFrame
    # ignore_index=True resets the index for the new combined file
    # pd.concat is smart and will handle columns that don't match
    # (filling missing ones with NaN, which is fine for ML)
    combined_df = pd.concat(all_data_frames, ignore_index=True)

    # Save the final, combined dataset to a CSV file
    output_filename = "labeled_dataset.csv"
    combined_df.to_csv(output_filename, index=False)

    print("\n" + "="*30)
    print(f"🎉 Success! Combined dataset saved to '{output_filename}'")
    print(f"Total events processed: {len(combined_df)}")
    print("\nLabel counts in the new dataset:")
    print(combined_df['label'].value_counts())
    print("="*30)
